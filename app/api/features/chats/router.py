from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.api.features.auth.dependencies import get_current_active_user
from app.api.features.chats.files import FILE_ALLOWED_CONTENT_TYPES, FILE_MAX_SIZE_BYTES, store_chat_file
from app.api.models.user import User
from app.api.rate_limiter import RateLimitConfig, limiter
from app.api.utils.user import get_user_db_row_by_username
from app.database.models.conversation_participants import ConversationParticipants
from app.database.models.conversation_read_cursors import ConversationReadCursor
from app.database.models.messages import Messages
from app.database.models.relationship import Relationship
from app.database.session import get_db

from .helpers import (
    advance_read_cursor,
    emit_contact_last_action_updates,
    emit_contact_last_message_updates,
    emit_conversation_event,
    emit_read_cursor_updated,
    get_conversation_max_seq,
    get_last_seen_seq,
    get_or_create_direct_conversation,
    is_conversation_participant,
    next_message_seq,
    normalize_emoji,
    normalize_reaction_user_ids,
    normalize_reactions_map,
    pair_filter,
    serialize_message,
    validate_direct_chat_access,
)
from .schemas import (
    DeleteMessageData,
    EditMessageData,
    ReactData,
    ReplyMessageData,
    SendMessageData,
    UpdateReadCursorData,
)


router = APIRouter(prefix="/chats", tags=["chats"])


@router.post("/v1/direct/{other_user_id}")
@limiter.limit(RateLimitConfig.WRITE)
def open_direct_conversation(
    other_user_id: int,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    request: Request,
):
    try:
        validate_direct_chat_access(db, current_user.id, other_user_id)
    except ValueError as exc:
        if str(exc) == "self":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.yourself")
        if str(exc) == "blocked":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.blocked")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="contacts.invalid_user")
    except PermissionError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="conversations.error.no_relation")

    conversation = get_or_create_direct_conversation(
        db,
        current_user.id,
        other_user_id,
    )

    my_last_seen_seq = get_last_seen_seq(db, conversation.id, current_user.id)
    unseen_messages_count = (
        db.query(Messages.id)
        .filter(
            Messages.conversation_id == conversation.id,
            Messages.sender_id != current_user.id,
            Messages.seq > my_last_seen_seq,
        )
        .count()
    )

    return {
        "id": conversation.id,
        "type": conversation.type,
        "direct_pair": conversation.direct_pair,
        "created_at": conversation.created_at,
        "notifications": unseen_messages_count,
    }


@router.post("/v1/{conversation_id}/messages")
@limiter.limit(RateLimitConfig.WRITE)
async def send_message(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    request: Request,
    data: SendMessageData,
    conversation_id: str,
):
    is_participant = is_conversation_participant(db, conversation_id, current_user.id)
    if not is_participant:
        raise HTTPException(status_code=403, detail="conversations.error.not_participating")

    if not data.text and not data.file:
        raise HTTPException(status_code=400, detail="conversations.error.empty_message")

    if data.text and (len(data.text) < 0 or len(data.text) > 2048):
        raise HTTPException(status_code=422, detail="conversations.error.too_long")

    message_type = "text"
    content_payload = {}

    if data.file:
        file_to_store = await data.file.read()
        if not file_to_store:
            raise HTTPException(status_code=400, detail="conversations.error.missing_file")

        if len(file_to_store) > FILE_MAX_SIZE_BYTES:
            raise HTTPException(status_code=400, detail="conversations.error.file_too_big")

        content_type = (data.file.content_type or "application/octet-stream").lower()
        filename = data.file.filename or "file.bin"

        if content_type not in FILE_ALLOWED_CONTENT_TYPES:
            raise HTTPException(status_code=400, detail="conversations.error.file_type_not_accepted")

        try:
            file_url, width, height = store_chat_file(
                conversation_id=conversation_id,
                file_bytes=file_to_store,
                content_type=content_type,
                filename=filename
            )
        except RuntimeError as exc:
            raise HTTPException(status_code=500, detail=str(exc))

        message_type = "file"
        content_payload = {
            "url": file_url,
            "filename": filename,
            "content_type": content_type,
            "size": len(file_to_store)
        }
        if width and height:
            content_payload["width"] = width
            content_payload["height"] = height
        
        if data.text:
            content_payload["text"] = data.text
    else:
        content_payload = {"text": data.text}

    message = Messages(
        conversation_id=conversation_id,
        sender_id=current_user.id,
        seq=next_message_seq(db, conversation_id),
        type=message_type,
        content=content_payload,
    )

    other_participant_id = (
        db.query(ConversationParticipants.user_id)
        .filter(
            ConversationParticipants.conversation_id == conversation_id,
            ConversationParticipants.user_id != current_user.id
        )
        .scalar()
    )

    now = datetime.now(timezone.utc)
    if other_participant_id:
        (
            db.query(Relationship)
            .filter(pair_filter(current_user.id, other_participant_id))
            .filter(Relationship.relation == "contact")
            .update({Relationship.updated_at: now}, synchronize_session=False)
        )

    db.add(message)
    db.commit()
    db.refresh(message)

    if other_participant_id:
        emit_contact_last_action_updates(db, current_user.id, [other_participant_id], now)
        emit_contact_last_message_updates(db, current_user.id, [other_participant_id], message)

    response = serialize_message(message)
    emit_conversation_event(
        db,
        conversation_id,
        "message.created",
        {
            "message": response,
        },
    )

    return response


@router.get("/v1/{conversation_id}/messages")
@limiter.limit(RateLimitConfig.READ)
def fetch_messages(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    conversation_id: str,
    request: Request,
    limit: int = 20,
    before: datetime | None = None,
):
    is_participant = is_conversation_participant(db, conversation_id, current_user.id)

    if not is_participant:
        raise HTTPException(status_code=403, detail="conversations.error.not_participating")

    query = (
        db.query(Messages)
        .filter(Messages.conversation_id == conversation_id)
    )

    if before:
        query = query.filter(Messages.created_at < before)

    messages = (
        query
        .order_by(Messages.seq.desc())
        .limit(limit)
        .all()
    )

    messages.reverse()

    cursor_rows = (
        db.query(ConversationReadCursor.user_id, ConversationReadCursor.last_seen_seq)
        .filter(ConversationReadCursor.conversation_id == conversation_id)
        .all()
    )
    cursor_by_user_id = {
        user_id: int(last_seen_seq or 0)
        for (user_id, last_seen_seq) in cursor_rows
    }
    my_last_seen_seq = cursor_by_user_id.get(current_user.id, 0)
    max_other_last_seen_seq = max(
        (seq for user_id, seq in cursor_by_user_id.items() if user_id != current_user.id),
        default=0,
    )

    payload = []
    for message in messages:
        is_seen = (
            max_other_last_seen_seq >= message.seq
            if message.sender_id == current_user.id
            else my_last_seen_seq >= message.seq
        )
        payload.append(serialize_message(message, seen_override=is_seen))

    if before is None and messages:
        previous_seq, next_seq, last_seen_at = advance_read_cursor(
            db,
            conversation_id,
            current_user.id,
            messages[-1].seq,
        )
        db.commit()
        if next_seq > previous_seq:
            emit_read_cursor_updated(
                db,
                conversation_id,
                current_user.id,
                next_seq,
                last_seen_at,
            )

    return payload


@router.post("/v1/{conversation_id}/read-cursor")
@limiter.limit(RateLimitConfig.WRITE)
def update_read_cursor(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: UpdateReadCursorData,
    request: Request,
    conversation_id: str,
):
    is_participant = is_conversation_participant(db, conversation_id, current_user.id)

    if not is_participant:
        raise HTTPException(status_code=403, detail="conversations.error.not_participating")

    previous_seq, next_seq, last_seen_at = advance_read_cursor(
        db,
        conversation_id,
        current_user.id,
        data.upto_seq,
    )
    db.commit()

    if next_seq > previous_seq:
        emit_read_cursor_updated(
            db,
            conversation_id,
            current_user.id,
            next_seq,
            last_seen_at,
        )

    return {
        "conversation_id": conversation_id,
        "reader_id": current_user.id,
        "last_seen_seq": next_seq,
        "updated": max(0, next_seq - previous_seq),
    }


@router.post("/v1/{conversation_id}/seen")
@limiter.limit(RateLimitConfig.WRITE)
def mark_conversation_seen(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    conversation_id: str,
    request: Request,
):
    is_participant = is_conversation_participant(db, conversation_id, current_user.id)

    if not is_participant:
        raise HTTPException(status_code=403, detail="conversations.error.not_participating")

    previous_seq, next_seq, last_seen_at = advance_read_cursor(
        db,
        conversation_id,
        current_user.id,
        get_conversation_max_seq(db, conversation_id),
    )
    db.commit()

    if next_seq > previous_seq:
        emit_read_cursor_updated(
            db,
            conversation_id,
            current_user.id,
            next_seq,
            last_seen_at,
        )

    return {
        "conversation_id": conversation_id,
        "reader_id": current_user.id,
        "seen_message_ids": [],
        "updated": max(0, next_seq - previous_seq),
        "last_seen_seq": next_seq,
    }


@router.post("/v1/{conversation_id}/reply")
@limiter.limit(RateLimitConfig.WRITE)
def reply_message(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: ReplyMessageData,
    request: Request,
    conversation_id: str,
):
    is_participant = is_conversation_participant(db, conversation_id, current_user.id)

    if not is_participant:
        raise HTTPException(status_code=403, detail="conversations.error.not_participating")

    if len(data.text) < 0 or len(data.text) > 2048:
        raise HTTPException(status_code=422, detail="conversations.error.too_long")

    parent_message = db.query(Messages).filter(
        Messages.conversation_id == conversation_id,
        Messages.id == data.message_id,
        Messages.type == "text",
    ).first()
    if not parent_message:
        raise HTTPException(status_code=422, detail="conversations.error.invalid_message")

    message = Messages(
        conversation_id=conversation_id,
        sender_id=current_user.id,
        seq=next_message_seq(db, conversation_id),
        type="text",
        content={
            "text": data.text,
            "reply_to": {
                "id": parent_message.id,
                "content": {
                    "text": parent_message.content["text"],
                },
                "created_at": parent_message.created_at.isoformat() if parent_message.created_at else None,
                "sender_id": parent_message.sender_id,
                "type": parent_message.type,
            },
        },
    )

    participant_ids = [
        user_id
        for (user_id,) in db.query(ConversationParticipants.user_id)
        .filter(ConversationParticipants.conversation_id == conversation_id)
        .all()
    ]
    now = datetime.now(timezone.utc)
    for other_user_id in participant_ids:
        if other_user_id == current_user.id:
            continue
        (
            db.query(Relationship)
            .filter(pair_filter(current_user.id, other_user_id))
            .filter(Relationship.relation == "contact")
            .update({Relationship.updated_at: now}, synchronize_session=False)
        )

    db.add(message)
    db.commit()
    db.refresh(message)

    emit_contact_last_action_updates(
        db,
        current_user.id,
        [user_id for user_id in participant_ids if user_id != current_user.id],
        now,
    )

    response = serialize_message(message)
    emit_conversation_event(
        db,
        conversation_id,
        "message.created",
        {
            "message": response,
        },
    )

    return response


@router.delete("/v1/{conversation_id}/messages", status_code=200)
@limiter.limit(RateLimitConfig.WRITE)
def delete_message(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: DeleteMessageData,
    request: Request,
    conversation_id: str,
):
    is_participant = is_conversation_participant(db, conversation_id, current_user.id)

    if not is_participant:
        raise HTTPException(status_code=403, detail="conversations.error.not_participating")

    message = db.query(Messages).filter(
        Messages.conversation_id == conversation_id,
        Messages.id == data.message_id,
        Messages.type == "text",
    ).first()
    if not message:
        raise HTTPException(status_code=422, detail="conversations.error.invalid_message")

    if message.sender_id != current_user.id:
        raise HTTPException(status_code=403, detail="conversations.error.no_permission")

    deleted_message_id = message.id

    db.delete(message)
    db.commit()

    emit_conversation_event(
        db,
        conversation_id,
        "message.deleted",
        {
            "message_id": deleted_message_id,
            "deleted_by": current_user.id,
        },
    )

    return JSONResponse(
        status_code=200,
        content={"message": "conversations.deleted_message"},
    )


@router.patch("/v1/{conversation_id}/messages")
@limiter.limit(RateLimitConfig.WRITE)
def edit_message(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: EditMessageData,
    request: Request,
    conversation_id: str,
):
    is_participant = is_conversation_participant(db, conversation_id, current_user.id)

    if len(data.text) < 0 or len(data.text) > 2048:
        raise HTTPException(status_code=422, detail="conversations.error.too_long")

    if not is_participant:
        raise HTTPException(status_code=403, detail="conversations.error.not_participating")

    message: Messages = db.query(Messages).filter(
        Messages.conversation_id == conversation_id,
        Messages.id == data.message_id,
        Messages.type == "text",
    ).first()
    if not message:
        raise HTTPException(status_code=422, detail="conversations.error.invalid_message")

    if message.sender_id != current_user.id:
        raise HTTPException(status_code=422, detail="conversations.error.no_permission")

    participant_ids = [
        user_id
        for (user_id,) in db.query(ConversationParticipants.user_id)
        .filter(ConversationParticipants.conversation_id == conversation_id)
        .all()
    ]
    now = datetime.now(timezone.utc)
    for other_user_id in participant_ids:
        if other_user_id == current_user.id:
            continue
        (
            db.query(Relationship)
            .filter(pair_filter(current_user.id, other_user_id))
            .filter(Relationship.relation == "contact")
            .update({Relationship.updated_at: now}, synchronize_session=False)
        )

    edit_time = datetime.now(timezone.utc)
    content = dict(message.content or {})

    previous_text = content.get("text")
    if isinstance(previous_text, str):
        history = content.get("history")
        if not isinstance(history, list):
            history = []
        history.append(
            {
                "text": previous_text,
                "date": edit_time.isoformat(),
            }
        )
        content["history"] = history

    content["text"] = data.text
    message.content = content

    message.edited_at = edit_time

    db.commit()
    db.refresh(message)

    emit_contact_last_action_updates(
        db,
        current_user.id,
        [user_id for user_id in participant_ids if user_id != current_user.id],
        now,
    )

    response = serialize_message(message)
    emit_conversation_event(
        db,
        conversation_id,
        "message.edited",
        {
            "message": response,
        },
    )

    return response


@router.post("/v1/{conversation_id}/messages/{message_id}/reactions")
@limiter.limit(RateLimitConfig.WRITE)
def add_reaction(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: ReactData,
    request: Request,
    conversation_id: str,
    message_id: str,
):
    is_participant = is_conversation_participant(db, conversation_id, current_user.id)

    if not is_participant:
        raise HTTPException(status_code=403, detail="conversations.error.not_participating")

    try:
        normalized_emoji = normalize_emoji(data.emoji)
    except ValueError:
        raise HTTPException(status_code=422, detail="conversations.error.invalid_reaction")

    message: Messages = db.query(Messages).filter(
        Messages.conversation_id == conversation_id,
        Messages.id == message_id,
    ).first()
    if not message:
        raise HTTPException(status_code=422, detail="conversations.error.invalid_message")

    reactions = normalize_reactions_map(message.reactions)

    if normalized_emoji not in reactions and len(reactions.keys()) >= 16:
        raise HTTPException(status_code=422, detail="conversations.error.too_many_reactions")

    now_iso = datetime.now(timezone.utc).isoformat()
    existing = reactions.get(normalized_emoji) or {}
    user_list = normalize_reaction_user_ids(existing.get("user_ids"))

    if current_user.id not in user_list:
        user_list.append(current_user.id)

    reactions[normalized_emoji] = {
        "user_ids": user_list,
        "first_added_at": existing.get("first_added_at") or now_iso,
    }

    message.reactions = reactions
    db.commit()
    db.refresh(message)

    response = serialize_message(message)
    emit_conversation_event(
        db,
        conversation_id,
        "message.reacted",
        {
            "message": response,
        },
    )

    return response


@router.delete("/v1/{conversation_id}/messages/{message_id}/reactions")
@limiter.limit(RateLimitConfig.WRITE)
def remove_reaction(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_active_user)],
    data: ReactData,
    request: Request,
    conversation_id: str,
    message_id: str,
):
    is_participant = is_conversation_participant(db, conversation_id, current_user.id)

    if not is_participant:
        raise HTTPException(status_code=403, detail="conversations.error.not_participating")

    try:
        normalized_emoji = normalize_emoji(data.emoji)
    except ValueError:
        raise HTTPException(status_code=422, detail="conversations.error.invalid_reaction")

    message: Messages = db.query(Messages).filter(
        Messages.conversation_id == conversation_id,
        Messages.id == message_id,
    ).first()
    if not message:
        raise HTTPException(status_code=422, detail="conversations.error.invalid_message")

    reactions = normalize_reactions_map(message.reactions)
    existing = reactions.get(normalized_emoji) or {}
    user_list = normalize_reaction_user_ids(existing.get("user_ids"))
    if current_user.id in user_list:
        user_list = [uid for uid in user_list if uid != current_user.id]
        if user_list:
            reactions[normalized_emoji] = {
                "user_ids": user_list,
                "first_added_at": existing.get("first_added_at"),
            }
        else:
            reactions.pop(normalized_emoji, None)

    message.reactions = reactions
    db.commit()
    db.refresh(message)

    response = serialize_message(message)
    emit_conversation_event(
        db,
        conversation_id,
        "message.reacted",
        {
            "message": response,
        },
    )

    return response

# @router.post("/v1/{conversation_id}/files")
# @limiter.limit(RateLimitConfig.WRITE)
# async def upload_chat_file(
#     conversation_id: str,
#     request: Request,
#     file: Annotated[UploadFile, File(...)],
#     db: Annotated[Session, Depends(get_db)],
#     current_user: Annotated[User, Depends(get_current_active_user)],
# ):
#     is_participant = is_conversation_participant(db, conversation_id, current_user.id)
#     if not is_participant:
#         raise HTTPException(status_code=403, detail="conversations.error.not_participating")

#     file_to_store = await file.read()
#     if not file_to_store:
#         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="conversations.error.missing_file")

#     if len(file_to_store) > FILE_MAX_SIZE_BYTES:
#         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="conversations.error.file_too_big")

#     content_type = (file.content_type or "application/octet-stream").lower()
#     filename = file.filename or "file.bin"

#     if content_type not in FILE_ALLOWED_CONTENT_TYPES:
#         raise HTTPException(status_code=400, detail="conversations.error.file_type_not_accepted")

#     try:
#         file_url, width, height = store_chat_file(
#             conversation_id=conversation_id,
#             file_bytes=file_to_store,
#             content_type=content_type,
#             filename=filename
#         )
#     except RuntimeError as exc:
#         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))

#     content_payload = {
#         "url": file_url,
#         "filename": filename,
#         "content_type": content_type,
#         "size": len(file_to_store)
#     }
    
#     if width and height:
#         content_payload["width"] = width
#         content_payload["height"] = height

#     message = Messages(
#         conversation_id=conversation_id,
#         sender_id=current_user.id,
#         seq=next_message_seq(db, conversation_id),
#         type="file",
#         content=content_payload,
#     )

#     participant_ids = [
#         user_id for (user_id,) in db.query(ConversationParticipants.user_id)
#         .filter(ConversationParticipants.conversation_id == conversation_id).all()
#     ]
    
#     now = datetime.now(timezone.utc)
#     for other_user_id in participant_ids:
#         if other_user_id == current_user.id:
#             continue
#         db.query(Relationship).filter(pair_filter(current_user.id, other_user_id)).filter(
#             Relationship.relation == "contact"
#         ).update({Relationship.updated_at: now}, synchronize_session=False)

#     db.add(message)
#     db.commit()
#     db.refresh(message)

# #    emit_contact_last_action_updates(db, current_user.id, [uid for uid in participant_ids if uid != current_user.id], now)
# #    emit_contact_last_message_updates(db, current_user.id, [uid for uid in participant_ids if uid != current_user.id], message)

#     response = serialize_message(message)
# #    emit_conversation_event(db, conversation_id, "message.created", {"message": response})

#     return response
import io
import mimetypes
import os
import secrets
from urllib.parse import urlparse

FILE_ALLOWED_CONTENT_TYPES = {
    # Core Images
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
    "image/gif": "gif",
    "image/heic": "heic",
    
    # Videos
    "video/mp4": "mp4",
    "video/quicktime": "mov",
    "video/webm": "webm",
    
    # Audio
    "audio/mpeg": "mp3",
    "audio/ogg": "ogg",
    "audio/aac": "aac",
    "audio/m4a": "m4a",
    
    # Documents
    "application/pdf": "pdf",
    "text/plain": "txt",
    "text/csv": "csv",
    "application/zip": "zip",
    "application/msword": "doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    "application/vnd.ms-excel": "xls",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
    "application/vnd.ms-powerpoint": "ppt",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "pptx",
}

FILE_MAX_SIZE_BYTES = 15 * 1024 * 1024

def _get_image_dimensions(file_bytes: bytes) -> tuple[int | None, int | None]:
    try:
        from PIL import Image
        with Image.open(io.BytesIO(file_bytes)) as img:
            return img.width, img.height
    except Exception:
        return None, None


def store_chat_file(*, conversation_id: str, file_bytes: bytes, content_type: str, filename: str) -> tuple[str, int | None, int | None]:
    endpoint_raw = os.getenv("S3_ENDPOINT", "http://localhost:9000").strip()
    parsed_endpoint = urlparse(endpoint_raw)
    endpoint = parsed_endpoint.netloc or parsed_endpoint.path
    secure = parsed_endpoint.scheme == "https"

    access_key = (os.getenv("S3_ACCESS_KEY") or os.getenv("MINIO_ROOT_USER") or "").strip()
    secret_key = (os.getenv("S3_SECRET_KEY") or os.getenv("MINIO_ROOT_PASSWORD") or "").strip()
    bucket = (os.getenv("S3_BUCKET_FILES") or "amber-files").strip()
    region = (os.getenv("S3_REGION") or "us-east-1").strip()

    if not endpoint or not access_key or not secret_key:
        raise RuntimeError("File storage is not configured")

    extension = mimetypes.guess_extension(content_type)
    if extension:
        extension = extension.lstrip(".")
    else:
        extension = FILE_ALLOWED_CONTENT_TYPES.get(content_type, "bin")

    if "." in filename:
        extension = filename.split(".")[-1]

    width, height = _get_image_dimensions(file_bytes)

    try:
        from minio import Minio
        from minio.error import S3Error
    except ModuleNotFoundError as exc:
        raise RuntimeError("MinIO dependency is not installed") from exc

    client = Minio(
        endpoint,
        access_key=access_key,
        secret_key=secret_key,
        secure=secure,
        region=region,
    )

    object_key = f"chats/{conversation_id}/{secrets.token_hex(16)}.{extension}"

    try:
        client.put_object(
            bucket,
            object_key,
            io.BytesIO(file_bytes),
            length=len(file_bytes),
            content_type=content_type,
        )
    except S3Error as exc:
        raise RuntimeError("File upload failed") from exc

    public_base = (os.getenv("S3_PUBLIC_BASE_URL") or "").strip()
    if not public_base:
        scheme = "https" if secure else "http"
        public_base = f"{scheme}://{endpoint}"

    url = f"{public_base.rstrip('/')}/{bucket}/{object_key}"
    return url, width, height
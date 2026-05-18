import io
import os
import secrets
from urllib.parse import urlparse


AVATAR_ALLOWED_CONTENT_TYPES = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
}
AVATAR_MAX_SIZE_BYTES = 5 * 1024 * 1024


def _prepare_avatar_image(*, file_bytes: bytes, content_type: str) -> bytes:
    try:
        from PIL import Image, ImageOps
    except ModuleNotFoundError as exc:
        raise RuntimeError("Pillow dependency is not installed") from exc

    extension = AVATAR_ALLOWED_CONTENT_TYPES.get(content_type)
    if extension is None:
        raise RuntimeError("Unsupported avatar content type")
    format_name = {
        "image/jpeg": "JPEG",
        "image/png": "PNG",
        "image/webp": "WEBP",
    }[content_type]

    with Image.open(io.BytesIO(file_bytes)) as source_image:
        source_image = ImageOps.exif_transpose(source_image)

        has_alpha = "A" in source_image.getbands()
        if content_type == "image/jpeg":
            if source_image.mode != "RGB":
                if has_alpha:
                    background = Image.new("RGB", source_image.size, (255, 255, 255))
                    background.paste(source_image, mask=source_image.getchannel("A"))
                    source_image = background
                else:
                    source_image = source_image.convert("RGB")
        elif source_image.mode not in {"RGBA", "RGB"}:
            source_image = source_image.convert("RGBA" if has_alpha else "RGB")

        resampling = getattr(Image, "Resampling", None)
        if resampling is not None:
            resample_filter = resampling.LANCZOS
        else:
            resample_filter = getattr(Image, "LANCZOS")
        processed_image = ImageOps.fit(source_image, (256, 256), method=resample_filter)

        output = io.BytesIO()
        save_kwargs: dict[str, object] = {"optimize": True}
        if content_type == "image/jpeg":
            save_kwargs.update({"quality": 85, "progressive": True})
        elif content_type == "image/png":
            save_kwargs.update({"compress_level": 9})
        elif content_type == "image/webp":
            save_kwargs.update({"quality": 85, "method": 6})

        processed_image.save(output, format=format_name, **save_kwargs)

    return output.getvalue()


def store_avatar_image(*, username: str, file_bytes: bytes, content_type: str) -> str:
    endpoint_raw = os.getenv("S3_ENDPOINT", "http://localhost:9000").strip()
    parsed_endpoint = urlparse(endpoint_raw)
    endpoint = parsed_endpoint.netloc or parsed_endpoint.path
    secure = parsed_endpoint.scheme == "https"

    access_key = (os.getenv("S3_ACCESS_KEY") or os.getenv("MINIO_ROOT_USER") or "").strip()
    secret_key = (os.getenv("S3_SECRET_KEY") or os.getenv("MINIO_ROOT_PASSWORD") or "").strip()
    bucket = (os.getenv("S3_BUCKET_AVATARS") or "amber-avatars").strip()
    region = (os.getenv("S3_REGION") or "us-east-1").strip()

    if not endpoint or not access_key or not secret_key:
        raise RuntimeError("Avatar storage is not configured")

    extension = AVATAR_ALLOWED_CONTENT_TYPES.get(content_type)
    if extension is None:
        raise RuntimeError("Unsupported avatar content type")

    processed_file_bytes = _prepare_avatar_image(file_bytes=file_bytes, content_type=content_type)

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

    object_key = f"avatars/{username}/{secrets.token_hex(16)}.{extension}"

    try:
        client.put_object(
            bucket,
            object_key,
            io.BytesIO(processed_file_bytes),
            length=len(processed_file_bytes),
            content_type=content_type,
        )
    except S3Error as exc:
        raise RuntimeError("Avatar upload failed") from exc

    public_base = (os.getenv("S3_PUBLIC_BASE_URL") or "").strip()
    if not public_base:
        scheme = "https" if secure else "http"
        public_base = f"{scheme}://{endpoint}"

    return f"{public_base.rstrip('/')}/{bucket}/{object_key}"


def remove_avatar_image(*, avatar_url: str) -> None:
    endpoint_raw = os.getenv("S3_ENDPOINT", "http://localhost:9000").strip()
    parsed_endpoint = urlparse(endpoint_raw)
    endpoint = parsed_endpoint.netloc or parsed_endpoint.path
    secure = parsed_endpoint.scheme == "https"

    access_key = (os.getenv("S3_ACCESS_KEY") or os.getenv("MINIO_ROOT_USER") or "").strip()
    secret_key = (os.getenv("S3_SECRET_KEY") or os.getenv("MINIO_ROOT_PASSWORD") or "").strip()
    bucket = (os.getenv("S3_BUCKET_AVATARS") or "amber-avatars").strip()
    region = (os.getenv("S3_REGION") or "us-east-1").strip()

    if not endpoint or not access_key or not secret_key or not bucket:
        return

    parsed_url = urlparse(avatar_url)
    if not parsed_url.path:
        return

    path = parsed_url.path.lstrip("/")
    bucket_prefix = f"{bucket}/"
    if not path.startswith(bucket_prefix):
        return

    object_key = path[len(bucket_prefix):]
    if not object_key:
        return

    try:
        from minio import Minio
    except ModuleNotFoundError:
        return

    client = Minio(
        endpoint,
        access_key=access_key,
        secret_key=secret_key,
        secure=secure,
        region=region,
    )

    try:
        client.remove_object(bucket, object_key)
    except Exception:
        return

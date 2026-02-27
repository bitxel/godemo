"""
Expose a local service that is already running on port 8000.

Usage:
    # Start your local app first, then:
    python expose_example.py

    # Or with a custom gateway:
    GODEMO_GATEWAY_URL=http://127.0.0.1:8080 python expose_example.py
"""
import godemo


def main() -> None:
    tunnel = godemo.expose(8000)
    print("Public URL:", tunnel.public_url)
    try:
        input("Press Enter to stop...")
    finally:
        tunnel.close()


if __name__ == "__main__":
    main()

import reflex as rx

config = rx.Config(
    app_name="reflex_fastapi_examples",
    plugins=[
        rx.plugins.SitemapPlugin(),
    ],
)

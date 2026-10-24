
import os
import hmac
import hashlib
import base64
import uuid

import boto3
import pymysql

from botocore.exceptions import ClientError
from dotenv import load_dotenv
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY is missing from .env")

app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

COGNITO_USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")
COGNITO_CLIENT_ID = os.getenv("COGNITO_CLIENT_ID")
COGNITO_CLIENT_SECRET = os.getenv("COGNITO_CLIENT_SECRET")

RDS_HOST = os.getenv("RDS_HOST")
RDS_PORT = int(os.getenv("RDS_PORT", "3306"))
RDS_USER = os.getenv("RDS_USER")
RDS_PASSWORD = os.getenv("RDS_PASSWORD")
RDS_DATABASE = os.getenv("RDS_DATABASE", "recipedb")

S3_BUCKET = os.getenv("S3_BUCKET_NAME")

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}

cognito = boto3.client(
    "cognito-idp",
    region_name=AWS_REGION
)

s3 = boto3.client(
    "s3",
    region_name=AWS_REGION
)


def get_secret_hash(username):
    message = username + COGNITO_CLIENT_ID

    digest = hmac.new(
        COGNITO_CLIENT_SECRET.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256
    ).digest()

    return base64.b64encode(digest).decode()


def get_db_connection():
    return pymysql.connect(
        host=RDS_HOST,
        port=RDS_PORT,
        user=RDS_USER,
        password=RDS_PASSWORD,
        database=RDS_DATABASE,
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=8,
        autocommit=False
    )


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


def make_image_url(image_key):
    if not image_key or not S3_BUCKET:
        return None

    try:
        return s3.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": S3_BUCKET,
                "Key": image_key
            },
            ExpiresIn=3600
        )
    except ClientError:
        app.logger.exception("Could not create image URL")
        return None


@app.route("/")
def home():
    conn = None

    try:
        conn = get_db_connection()

        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT
                    recipe_id,
                    user_email,
                    title,
                    description,
                    image_key,
                    created_at
                FROM recipes
                ORDER BY created_at DESC
            """)

            recipes = cursor.fetchall()

            for recipe in recipes:
                recipe["image_url"] = make_image_url(
                    recipe["image_key"]
                )

                cursor.execute("""
                    SELECT
                        rating_id,
                        user_email,
                        rating,
                        comment,
                        created_at
                    FROM ratings
                    WHERE recipe_id = %s
                    ORDER BY created_at DESC
                """, (recipe["recipe_id"],))

                recipe["ratings"] = cursor.fetchall()

                cursor.execute("""
                    SELECT
                        COUNT(*) AS review_count,
                        AVG(rating) AS average_rating
                    FROM ratings
                    WHERE recipe_id = %s
                """, (recipe["recipe_id"],))

                summary = cursor.fetchone()
                recipe["review_count"] = summary["review_count"]
                recipe["average_rating"] = summary["average_rating"]

        return render_template(
            "index.html",
            recipes=recipes,
            user_email=session.get("user_email")
        )

    except Exception:
        app.logger.exception("Could not load recipes")
        return "Unable to load recipes. Check the application logs.", 500

    finally:
        if conn:
            conn.close()


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Enter your email and password.", "error")
            return redirect(url_for("signup"))

        try:
            cognito.sign_up(
                ClientId=COGNITO_CLIENT_ID,
                SecretHash=get_secret_hash(email),
                Username=email,
                Password=password,
                UserAttributes=[
                    {
                        "Name": "email",
                        "Value": email
                    }
                ]
            )

            flash(
                "Signup successful. Confirm your account if required, "
                "then log in.",
                "success"
            )
            return redirect(url_for("login"))

        except cognito.exceptions.UsernameExistsException:
            flash("This account already exists. Try logging in.", "error")

        except cognito.exceptions.InvalidPasswordException:
            flash(
                "Password does not meet your Cognito password policy.",
                "error"
            )

        except Exception:
            app.logger.exception("Signup failed")
            flash("Signup failed. Check the application logs.", "error")

        return redirect(url_for("signup"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Enter your email and password.", "error")
            return redirect(url_for("login"))

        try:
            result = cognito.initiate_auth(
                ClientId=COGNITO_CLIENT_ID,
                AuthFlow="USER_PASSWORD_AUTH",
                AuthParameters={
                    "USERNAME": email,
                    "PASSWORD": password,
                    "SECRET_HASH": get_secret_hash(email)
                }
            )

            auth_result = result.get("AuthenticationResult")

            if not auth_result:
                flash(
                    "Additional authentication is required. "
                    "Check your Cognito configuration.",
                    "error"
                )
                return redirect(url_for("login"))

            session.clear()
            session["user_email"] = email
            session.permanent = True

            flash("Login successful.", "success")
            return redirect(url_for("home"))

        except cognito.exceptions.NotAuthorizedException:
            flash("Incorrect email or password.", "error")

        except cognito.exceptions.UserNotConfirmedException:
            flash(
                "Your account is not confirmed. Confirm it in Cognito.",
                "error"
            )

        except cognito.exceptions.PasswordResetRequiredException:
            flash("Your account requires a password reset.", "error")

        except Exception:
            app.logger.exception("Login failed")
            flash("Login failed. Check the application logs.", "error")

        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have logged out.", "success")
    return redirect(url_for("home"))


@app.route("/add-recipe", methods=["POST"])
def add_recipe():
    email = session.get("user_email")

    if not email:
        flash("Log in before sharing a recipe.", "error")
        return redirect(url_for("login"))

    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    image = request.files.get("image")

    if not title or not description:
        flash("Enter both a recipe title and description.", "error")
        return redirect(url_for("home"))

    if len(title) > 150:
        flash("The title must be 150 characters or fewer.", "error")
        return redirect(url_for("home"))

    image_key = None
    uploaded_key = None
    conn = None

    if image and image.filename:
        filename = secure_filename(image.filename)

        if not filename or not allowed_file(filename):
            flash(
                "Choose a JPG, JPEG, PNG, or WEBP image.",
                "error"
            )
            return redirect(url_for("home"))

        if not S3_BUCKET:
            flash("S3 bucket configuration is missing.", "error")
            return redirect(url_for("home"))

        extension = filename.rsplit(".", 1)[1].lower()
        image_key = f"recipes/{uuid.uuid4().hex}.{extension}"

        try:
            s3.upload_fileobj(
                image,
                S3_BUCKET,
                image_key,
                ExtraArgs={
                    "ContentType": (
                        "image/jpeg"
                        if extension in {"jpg", "jpeg"}
                        else f"image/{extension}"
                    )
                }
            )

            uploaded_key = image_key

        except Exception:
            app.logger.exception("S3 image upload failed")
            flash(
                "Image upload failed. Check S3 permissions and logs.",
                "error"
            )
            return redirect(url_for("home"))

    try:
        conn = get_db_connection()

        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO recipes
                    (user_email, title, description, image_key)
                VALUES (%s, %s, %s, %s)
            """, (email, title, description, image_key))

        conn.commit()
        flash("Recipe shared successfully!", "success")

    except Exception:
        if conn:
            conn.rollback()

        app.logger.exception("Could not save recipe")

        if uploaded_key:
            try:
                s3.delete_object(
                    Bucket=S3_BUCKET,
                    Key=uploaded_key
                )
            except Exception:
                app.logger.exception(
                    "Could not remove image after database failure"
                )

        flash("Could not save the recipe. Check the application logs.", "error")

    finally:
        if conn:
            conn.close()

    return redirect(url_for("home"))


@app.route("/rate/<int:recipe_id>", methods=["POST"])
def rate_recipe(recipe_id):
    email = session.get("user_email")

    if not email:
        flash("Log in to rate or comment on a recipe.", "error")
        return redirect(url_for("login"))

    try:
        rating = int(request.form.get("rating", "0"))
    except ValueError:
        rating = 0

    comment = request.form.get("comment", "").strip()

    if rating < 1 or rating > 5:
        flash("Choose a rating from 1 to 5.", "error")
        return redirect(url_for("home"))

    conn = None

    try:
        conn = get_db_connection()

        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT recipe_id FROM recipes WHERE recipe_id = %s",
                (recipe_id,)
            )

            if not cursor.fetchone():
                flash("Recipe not found.", "error")
                return redirect(url_for("home"))

            cursor.execute("""
                INSERT INTO ratings
                    (recipe_id, user_email, rating, comment)
                VALUES (%s, %s, %s, %s)
            """, (recipe_id, email, rating, comment or None))

        conn.commit()
        flash("Your rating and comment were saved.", "success")

    except Exception:
        if conn:
            conn.rollback()

        app.logger.exception("Could not save rating")
        flash("Could not save your rating. Check the application logs.", "error")

    finally:
        if conn:
            conn.close()

    return redirect(url_for("home"))


@app.route("/health")
def health():
    conn = None

    try:
        conn = get_db_connection()

        with conn.cursor() as cursor:
            cursor.execute("SELECT 1 AS result")
            cursor.fetchone()

        return {
            "status": "ok",
            "database": "connected"
        }, 200

    except Exception:
        app.logger.exception("Health check failed")
        return {
            "status": "error",
            "database": "unavailable"
        }, 500

    finally:
        if conn:
            conn.close()


@app.errorhandler(413)
def file_too_large(error):
    flash("Image is too large. Maximum size is 5 MB.", "error")
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=8080,
        debug=False
    )

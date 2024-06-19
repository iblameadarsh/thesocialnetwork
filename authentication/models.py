from datetime import datetime, timedelta

import jwt
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models
from django.utils import timezone

# Create your models here.


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser):
    name = models.CharField(max_length=125)
    email = models.EmailField(
        max_length=125,
        unique=True,
        null=True,
        blank=True
    )
    username = models.CharField(
        max_length=128,
        unique=True,
        blank=True,
        null=True,
    )
    phone_number = models.CharField(
        null=True,
        blank=True,
        unique=True,
        max_length=15
    )
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name',]

    def __str__(self):
        return self.email

    def get_username(self):
        """Return the username for this User."""
        return getattr(self, self.USERNAME_FIELD)

    @property
    def is_authenticated(self):
        """
        Always return True. This is a way to tell if the user has been
        authenticated in templates.
        """
        return True

    def set_password(self, raw_password):
        self.password = make_password(raw_password)
        self._password = raw_password

    def check_password(self, raw_password):
        """
        Return a boolean of whether the raw_password was correct. Handles
        hashing formats behind the scenes.
        """

        def setter(raw_password):
            self.set_password(raw_password)
            # Password hash upgrades shouldn't be considered password changes.
            self._password = None
            self.save(update_fields=["password"])

        return check_password(raw_password, self.password, setter)

    def _generate_jwt_token(self):
        """
        Generates a JSON Web Token that stores this user's ID and has an expiry
        date set to 30/60 minutes into the future.
        """
        if self.usergroup in ["Customer"]:
            dt = datetime.now() + timedelta(days=30, minutes=30)
        elif self.usergroup in ["Partner", "DoctorCustomer"]:
            dt = datetime.now() + timedelta(days=30, minutes=30)
        else:
            dt = datetime.now() + timedelta(days=1, minutes=60)
        token = jwt.encode(
            {
                "uuid": str(self.uuid),
                "exp": int(dt.timestamp()),
                "is_staff": self.is_staff,
                "user_group": self.usergroup,
            },
            settings.SECRET_KEY,
            algorithm="HS256",
        )

        return token  # .decode("utf-8")

    def _generate_refresh_token(self):
        """
        Generates a JSON Web Token that stores this user's ID and has an expiry
        date set to 30/7 days into the future.
        """
        if self.usergroup in ["Customer"]:
            dt = datetime.now() + timedelta(days=365)
        elif self.usergroup in ["Partner", "DoctorCustomer"]:
            dt = datetime.now() + timedelta(days=30)
        else:
            dt = datetime.now() + timedelta(days=7)
        token = jwt.encode(
            {
                "uuid": str(self.uuid),
                "exp": int(dt.timestamp()),
                "is_staff": self.is_staff,
                "user_group": self.usergroup,
            },
            settings.SECRET_KEY,
            algorithm="HS256",
        )

        return token


class FriendRequest(models.Model):
    from_user = models.ForeignKey(User, related_name='sent_requests', on_delete=models.CASCADE)
    to_user = models.ForeignKey(User, related_name='received_requests', on_delete=models.CASCADE)
    status = models.CharField(max_length=20, choices=[('pending', 'Pending'), ('accepted', 'Accepted'), ('rejected', 'Rejected')], default='pending')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('from_user', 'to_user')

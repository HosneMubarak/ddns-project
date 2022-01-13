from django.urls import path
from .views import home_page, login_page, signup_page, forgot_password_page, logout, services, single_service, root_home_page, reset_password_confirm, set_password_page

app_name = 'home'

urlpatterns = [
    path('', root_home_page, name="root_home_page"),
    path('controlpanel/', home_page, name="home_page"),
    path('login/', login_page, name="login_page"),
    path('signup/', signup_page, name="signup_page"),
    path('forgot_password/', forgot_password_page, name="forgot_password_page"),
    path('logout/', logout, name="logout"),
    path('services/', services, name="services"),
    path('services/single_service_update/<id>/', single_service, name="single_service"),
    path('password/reset/confirm/<uid>/<token>', reset_password_confirm, name="reset_password_confirm"),
    path('set_password/', set_password_page, name="set_password"),

]

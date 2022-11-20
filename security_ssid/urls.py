"""security_ssid URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import re_path as url
from django.contrib import admin
from django.urls import path

from .views import APDetail, APList, AppleMobile, AppleWloc, ClientDetail, \
    ClientList, LoadDB, SaveDB, locateSSID, stats, updateSSID

urlpatterns = [
    path('admin/', admin.site.urls),
    url(r'^$', ClientList.as_view(), name="clientlist"),
    url(r'^client/(?P<slug>[:\w]+)$', ClientDetail.as_view(), name="client"),
    url(r'^clients/?$', ClientList.as_view()),
    url(r'^network/(?P<ssid_or_bssid>.+)$', APDetail.as_view(), name="network"),
    url(r'^networks/?$', APList.as_view(), name="networks"),
    url(r'^apple-wloc/?$', AppleWloc, name="applewloc-base"),
    url(r'^savedb/(?P<name>[:\w]*)$', SaveDB, name="savedb"),
    url(r'^loaddb/(?P<name>[:\w]*)$', LoadDB, name="loaddb"),
    url(r'^apple-wloc/(?P<bssid>[:\w]+)$', AppleWloc, name="applewloc"),
    url(r'^apple-mobile/(?P<cellid>[:\w-]*)$', AppleMobile, name="apple-mobile"),
    url(r'^apple-mobile-lte/(?P<cellid>[:\w-]*)$', AppleMobile, {'LTE': True},
        name="apple-mobile-lte"),
    url(r'^updateSSID$', updateSSID, name="updatessid"),
    url(r'^locateSSID/?$', locateSSID, name="locatessid-base"),
    url(r'^locateSSID/(?P<ssid>[\w\W]+)$', locateSSID, name="locatessid"),
    url(r'^stats/?$', stats.as_view(), name="stats"),
]

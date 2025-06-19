package com.onetrust.otpublishers.headless.Internal.Network;

import retrofit2.InterfaceC5179d;
import retrofit2.http.f;
import retrofit2.http.k;
import retrofit2.http.o;
import retrofit2.http.y;

/* loaded from: classes2.dex */
public interface a {
    @k({"Content-Type: application/json"})
    @f
    InterfaceC5179d<String> a(@y String str);

    @k({"Content-Type: application/json"})
    @o
    InterfaceC5179d<String> a(@y String str, @retrofit2.http.a String str2);

    @k({"Content-Type: application/json"})
    @o
    InterfaceC5179d<String> b(@y String str);
}

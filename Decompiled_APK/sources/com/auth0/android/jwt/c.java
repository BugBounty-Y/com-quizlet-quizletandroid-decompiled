package com.auth0.android.jwt;

import com.google.gson.internal.m;
import com.google.gson.o;
import java.util.Date;

/* loaded from: classes.dex */
public final class c {
    public static Date a(o oVar, String str) {
        m mVar = oVar.a;
        if (mVar.containsKey(str)) {
            return new Date(((com.google.gson.m) mVar.get(str)).a() * 1000);
        }
        return null;
    }
}

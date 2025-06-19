package com.perimeterx.mobile_sdk.doctor_app.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c {
    public static boolean h;
    public String a;
    public com.perimeterx.mobile_sdk.doctor_app.state.d b;
    public boolean c;
    public boolean d;
    public boolean e;
    public boolean f;
    public boolean g;

    public final com.perimeterx.mobile_sdk.doctor_app.state.d a() {
        com.perimeterx.mobile_sdk.doctor_app.state.d dVar = this.b;
        if (dVar != null) {
            return dVar;
        }
        Intrinsics.m("state");
        throw null;
    }
}

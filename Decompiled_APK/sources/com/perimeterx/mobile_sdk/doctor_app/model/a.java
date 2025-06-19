package com.perimeterx.mobile_sdk.doctor_app.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final com.perimeterx.mobile_sdk.doctor_app.e a;
    public final com.perimeterx.mobile_sdk.doctor_app.state.d b;
    public final com.perimeterx.mobile_sdk.doctor_app.ui.i c;

    public a(com.perimeterx.mobile_sdk.doctor_app.e eVar) {
        this.a = eVar;
        this.b = null;
        this.c = null;
    }

    public a(com.perimeterx.mobile_sdk.doctor_app.state.d state) {
        Intrinsics.checkNotNullParameter(state, "state");
        this.a = com.perimeterx.mobile_sdk.doctor_app.e.a;
        this.b = state;
        this.c = null;
    }

    public a(com.perimeterx.mobile_sdk.doctor_app.ui.i popupType) {
        Intrinsics.checkNotNullParameter(popupType, "popupType");
        this.a = com.perimeterx.mobile_sdk.doctor_app.e.e;
        this.c = popupType;
        this.b = null;
    }
}

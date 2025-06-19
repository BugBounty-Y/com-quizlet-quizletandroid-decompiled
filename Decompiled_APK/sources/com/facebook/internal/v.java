package com.facebook.internal;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;

/* loaded from: classes.dex */
public final class v {
    public final boolean a;
    public final int b;
    public final EnumSet c;
    public final boolean d;
    public final C1558m e;
    public final boolean f;
    public final boolean g;
    public final JSONArray h;
    public final String i;
    public final String j;
    public final String k;
    public final String l;
    public final JSONArray m;
    public final JSONArray n;
    public final JSONArray o;
    public final JSONArray p;
    public final JSONArray q;
    public final JSONArray r;
    public final JSONArray s;
    public final ArrayList t;
    public final ArrayList u;
    public final ArrayList v;
    public final ArrayList w;
    public final Long x;

    public v(boolean z, String nuxContent, int i, EnumSet smartLoginOptions, HashMap dialogConfigurations, boolean z2, C1558m errorClassification, String smartLoginBookmarkIconURL, String smartLoginMenuIconURL, boolean z3, boolean z4, JSONArray jSONArray, String sdkUpdateMessage, String str, String str2, String str3, JSONArray jSONArray2, JSONArray jSONArray3, JSONArray jSONArray4, JSONArray jSONArray5, JSONArray jSONArray6, JSONArray jSONArray7, JSONArray jSONArray8, ArrayList arrayList, ArrayList arrayList2, ArrayList arrayList3, ArrayList arrayList4, Long l) {
        Intrinsics.checkNotNullParameter(nuxContent, "nuxContent");
        Intrinsics.checkNotNullParameter(smartLoginOptions, "smartLoginOptions");
        Intrinsics.checkNotNullParameter(dialogConfigurations, "dialogConfigurations");
        Intrinsics.checkNotNullParameter(errorClassification, "errorClassification");
        Intrinsics.checkNotNullParameter(smartLoginBookmarkIconURL, "smartLoginBookmarkIconURL");
        Intrinsics.checkNotNullParameter(smartLoginMenuIconURL, "smartLoginMenuIconURL");
        Intrinsics.checkNotNullParameter(sdkUpdateMessage, "sdkUpdateMessage");
        this.a = z;
        this.b = i;
        this.c = smartLoginOptions;
        this.d = z2;
        this.e = errorClassification;
        this.f = z3;
        this.g = z4;
        this.h = jSONArray;
        this.i = sdkUpdateMessage;
        this.j = str;
        this.k = str2;
        this.l = str3;
        this.m = jSONArray2;
        this.n = jSONArray3;
        this.o = jSONArray4;
        this.p = jSONArray5;
        this.q = jSONArray6;
        this.r = jSONArray7;
        this.s = jSONArray8;
        this.t = arrayList;
        this.u = arrayList2;
        this.v = arrayList3;
        this.w = arrayList4;
        this.x = l;
    }
}

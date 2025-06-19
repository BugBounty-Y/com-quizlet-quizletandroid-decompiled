package com.perimeterx.mobile_sdk.doctor_app.model;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import java.util.ArrayList;
import kotlin.A;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class g {
    public static final com.quizlet.shared.usecase.folderstudymaterials.b a;
    public static final g b;
    public static final g c;
    public static final g d;
    public static final g e;
    public static final g f;
    public static final g g;
    public static final g h;
    public static final g i;
    public static final g j;
    public static final g k;
    public static final g l;
    public static final g m;
    public static final g n;
    public static final g o;
    public static final g p;
    public static final g q;
    public static final g r;
    public static final g s;
    public static final g t;
    public static final /* synthetic */ g[] u;

    static {
        g gVar = new g("HEADER", 0);
        b = gVar;
        g gVar2 = new g("SECTION_CONFIGURATION", 1);
        c = gVar2;
        g gVar3 = new g("CONFIGURATION_START_INITIATED", 2);
        d = gVar3;
        g gVar4 = new g("CONFIGURATION_CONFIGURATION", 3);
        e = gVar4;
        g gVar5 = new g("SECTION_NATIVE", 4);
        f = gVar5;
        g gVar6 = new g("NATIVE_HEADERS", 5);
        g = gVar6;
        g gVar7 = new g("NATIVE_RESPONSE_HANDLER", 6);
        h = gVar7;
        g gVar8 = new g("NATIVE_MOBILE", 7);
        i = gVar8;
        g gVar9 = new g("NATIVE_CHALLENGE_SHOWN", 8);
        j = gVar9;
        g gVar10 = new g("NATIVE_CHALLENGE_DISMISSED", 9);
        k = gVar10;
        g gVar11 = new g("NATIVE_CALLBACK_CALLED", 10);
        l = gVar11;
        g gVar12 = new g("NATIVE_USER_ID_WAS_SET", 11);
        m = gVar12;
        g gVar13 = new g("NATIVE_DEVICE_FP", 12);
        n = gVar13;
        g gVar14 = new g("NATIVE_OUTGOING_URLS", 13);
        o = gVar14;
        g gVar15 = new g("NATIVE_ADDITIONAL_DATA", 14);
        p = gVar15;
        g gVar16 = new g("SECTION_WEB_VIEW", 15);
        q = gVar16;
        g gVar17 = new g("WEB_VIEW_SYNC", 16);
        r = gVar17;
        g gVar18 = new g("WEB_VIEW_CHALLENGE_SHOWN", 17);
        s = gVar18;
        g gVar19 = new g("WEB_VIEW_CHALLENGE_DISMISSED", 18);
        g gVar20 = new g("WEB_VIEW_MOBILE_DATA", 19);
        t = gVar20;
        g[] gVarArr = {gVar, gVar2, gVar3, gVar4, gVar5, gVar6, gVar7, gVar8, gVar9, gVar10, gVar11, gVar12, gVar13, gVar14, gVar15, gVar16, gVar17, gVar18, gVar19, gVar20};
        u = gVarArr;
        AbstractC3328d.f(gVarArr);
        a = new com.quizlet.shared.usecase.folderstudymaterials.b(22);
    }

    public static g valueOf(String str) {
        return (g) Enum.valueOf(g.class, str);
    }

    public static g[] values() {
        return (g[]) u.clone();
    }

    public final A a() {
        switch (ordinal()) {
            case 2:
                return new A(0);
            case 3:
                return new A(1);
            case 4:
            case 15:
            default:
                return null;
            case 5:
                return new A(2);
            case 6:
                return new A(3);
            case 7:
                return new A(4);
            case 8:
                return new A(5);
            case 9:
                return new A(6);
            case 10:
                return new A(7);
            case 11:
                return new A(2);
            case 12:
                return new A(3);
            case 13:
                return new A(4);
            case 14:
                return new A(5);
            case 16:
                return new A(8);
            case 17:
                return new A(9);
            case 18:
                return new A(10);
            case 19:
                return new A(8);
        }
    }

    public final String b() {
        switch (ordinal()) {
            case 1:
                return "Configuration";
            case 2:
                return "Start method";
            case 3:
                return "Configuration settings";
            case 4:
                return "Native app framework";
            case 5:
                return "Request headers";
            case 6:
                return "Initiate response";
            case 7:
                return "Mobile challenge";
            case 8:
                return "Display challenge";
            case 9:
                return "Dismiss challenge";
            case 10:
                return "Initiate callbacks";
            case 11:
                return "User ID was set";
            case 12:
                return "Device's fingerprint";
            case 13:
                return "Outgoing URLs were reported";
            case 14:
                return "Additional data was reported";
            case 15:
                return "Web view framework";
            case 16:
                return "Mobile challenge";
            case 17:
                return "Display challenge";
            case 18:
                return "Dismiss challenge";
            case 19:
                return "Mobile's data was set";
            default:
                return null;
        }
    }

    public final ArrayList c() {
        ArrayList arrayList = new ArrayList();
        int iOrdinal = ordinal();
        if (iOrdinal == 2) {
            arrayList.add("Make sure you call the SDK’s Start method from the onCreate method");
            return arrayList;
        }
        if (iOrdinal == 3) {
            arrayList.add("Retrieve your AppID from the PerimeterX portal and compare to the value you have entered in your code");
            return arrayList;
        }
        if (iOrdinal == 5) {
            arrayList.add("Make sure that the AppID in your code is the same as the AppID found in the Applications tab of the PerimeterX portal.");
            return arrayList;
        }
        if (iOrdinal == 6) {
            arrayList.add("Make sure you are sending the block response to the SDK.");
            return arrayList;
        }
        switch (iOrdinal) {
            case 10:
                arrayList.add("Make sure callbacks are properly set where necessary for the SDK events");
                break;
            case 11:
                arrayList.add("Make sure that the you are signed in into your application.");
                break;
            case 12:
                arrayList.add("Make sure that the AppID in your code is the same as the AppID found in the Applications tab of the PerimeterX portal.");
                break;
            case 13:
                arrayList.add("Make sure your application is sending outgoing URL requests to the SDK.");
                break;
        }
        return arrayList;
    }
}

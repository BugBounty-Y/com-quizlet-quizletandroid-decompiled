package com.quizlet.features.infra.models.upgrade;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import java.util.Set;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;
import retrofit2.adapter.rxjava3.d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class a {
    public static final d b;
    public static final Set c;
    public static final Set d;
    public static final a e;
    public static final a f;
    public static final a g;
    public static final a h;
    public static final a i;
    public static final a j;
    public static final a k;
    public static final a l;
    public static final a m;
    public static final a n;
    public static final a o;
    public static final a p;
    public static final a q;
    public static final a r;
    public static final a s;
    public static final a t;
    public static final a u;
    public static final a v;
    public static final a w;
    public static final a x;
    public static final a y;
    public static final /* synthetic */ a[] z;
    public final int a;

    static {
        a aVar = new a("UNKNOWN", 0, -1);
        e = aVar;
        a aVar2 = new a("SIGN_UP", 1, 0);
        f = aVar2;
        a aVar3 = new a("USER_SETTINGS", 2, 1);
        g = aVar3;
        a aVar4 = new a("REMOVE_ADS", 3, 2);
        a aVar5 = new a("IMAGE_UPLOAD", 4, 3);
        h = aVar5;
        a aVar6 = new a("PROMO_ENGINE", 5, 4);
        a aVar7 = new a("MENU", 6, 5);
        a aVar8 = new a("INTERSTITIAL_AD", 7, 6);
        i = aVar8;
        a aVar9 = new a("START_ACTIVITY", 8, 7);
        a aVar10 = new a("JOIN_LINK", 9, 8);
        a aVar11 = new a("OFFLINE", 10, 9);
        j = aVar11;
        a aVar12 = new a("DEEP_LINK", 11, 10);
        k = aVar12;
        a aVar13 = new a("CLASS_UPSELL", 12, 12);
        a aVar14 = new a("BOTTOM_NAV", 13, 13);
        a aVar15 = new a("ONBOARDING", 14, 14);
        a aVar16 = new a("SCAN_DOCUMENT", 15, 15);
        l = aVar16;
        a aVar17 = new a("HOME", 16, 16);
        a aVar18 = new a("RICH_TEXT_EDIT", 17, 17);
        m = aVar18;
        a aVar19 = new a("EXPLANATIONS_METERING_PAYWALL", 18, 18);
        n = aVar19;
        a aVar20 = new a("STUDY_PATH", 19, 19);
        a aVar21 = new a("EXPLANATIONS_UPSELL", 20, 20);
        o = aVar21;
        a aVar22 = new a("LEARN_METERING_PAYWALL", 21, 21);
        p = aVar22;
        a aVar23 = new a("TEST_METERING_PAYWALL", 22, 22);
        q = aVar23;
        a aVar24 = new a("PROFILE", 23, 23);
        r = aVar24;
        a aVar25 = new a("LEARN_METERING_TOAST", 24, 24);
        s = aVar25;
        a aVar26 = new a("TEST_METERING_TOAST", 25, 25);
        t = aVar26;
        a aVar27 = new a("SCAN_NOTES_METERING_PAYWALL", 26, 26);
        u = aVar27;
        a aVar28 = new a("SCAN_NOTES_METERING_TOAST", 27, 27);
        v = aVar28;
        a aVar29 = new a("DELAYED_SIGNUP_UPSELL", 28, 28);
        w = aVar29;
        a aVar30 = new a("PRACTICE_TEST_METERING_PAYWALL", 29, 29);
        x = aVar30;
        a aVar31 = new a("UPLOAD_PRACTICE_TEST_METERING_PAYWALL", 30, 30);
        y = aVar31;
        a[] aVarArr = {aVar, aVar2, aVar3, aVar4, aVar5, aVar6, aVar7, aVar8, aVar9, aVar10, aVar11, aVar12, aVar13, aVar14, aVar15, aVar16, aVar17, aVar18, aVar19, aVar20, aVar21, aVar22, aVar23, aVar24, aVar25, aVar26, aVar27, aVar28, aVar29, aVar30, aVar31};
        z = aVarArr;
        AbstractC3328d.f(aVarArr);
        b = new d(26);
        a[] elements = {aVar5, aVar16, aVar18};
        Intrinsics.checkNotNullParameter(elements, "elements");
        c = C4933y.T(elements);
        a[] elements2 = {aVar14, aVar17};
        Intrinsics.checkNotNullParameter(elements2, "elements");
        C4933y.T(elements2);
        a[] elements3 = {aVar2, aVar29};
        Intrinsics.checkNotNullParameter(elements3, "elements");
        d = C4933y.T(elements3);
    }

    public a(String str, int i2, int i3) {
        this.a = i3;
    }

    public static a valueOf(String str) {
        return (a) Enum.valueOf(a.class, str);
    }

    public static a[] values() {
        return (a[]) z.clone();
    }
}

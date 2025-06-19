package com.braze.enums;

import com.braze.models.IPutIntoJson;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.onetrust.otpublishers.headless.Public.OTCCPAGeolocationConstants;
import java.util.LinkedHashMap;
import kotlin.collections.U;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes.dex */
public final class e implements IPutIntoJson {
    public static final e A;
    public static final e B;
    public static final e C;
    public static final e D;
    public static final e E;
    public static final e F;
    public static final e G;
    public static final e H;
    public static final e I;
    public static final e J;
    public static final e K;
    public static final e L;
    public static final /* synthetic */ e[] M;
    public static final d b;
    public static final LinkedHashMap c;
    public static final e d;
    public static final e e;
    public static final e f;
    public static final e g;
    public static final e h;
    public static final e i;
    public static final e j;
    public static final e k;
    public static final e l;
    public static final e m;
    public static final e n;
    public static final e o;
    public static final e p;
    public static final e q;
    public static final e r;
    public static final e s;
    public static final e t;
    public static final e u;
    public static final e v;
    public static final e w;
    public static final e x;
    public static final e y;
    public static final e z;
    public final String a;

    static {
        e eVar = new e("LOCATION_RECORDED", 0, "lr");
        d = eVar;
        e eVar2 = new e("CUSTOM_EVENT", 1, "ce");
        e = eVar2;
        e eVar3 = new e("PURCHASE", 2, "p");
        f = eVar3;
        e eVar4 = new e("PUSH_STORY_PAGE_CLICK", 3, "cic");
        g = eVar4;
        e eVar5 = new e("PUSH_CLICKED", 4, "pc");
        h = eVar5;
        e eVar6 = new e("PUSH_ACTION_BUTTON_CLICKED", 5, OTCCPAGeolocationConstants.CA);
        i = eVar6;
        e eVar7 = new e("INTERNAL", 6, "i");
        j = eVar7;
        e eVar8 = new e("INTERNAL_ERROR", 7, "ie");
        k = eVar8;
        e eVar9 = new e("NEWS_FEED_CARD_IMPRESSION", 8, "ci");
        l = eVar9;
        e eVar10 = new e("NEWS_FEED_CARD_CLICK", 9, "cc");
        m = eVar10;
        e eVar11 = new e("GEOFENCE", 10, "g");
        n = eVar11;
        e eVar12 = new e("CONTENT_CARDS_CLICK", 11, "ccc");
        o = eVar12;
        e eVar13 = new e("CONTENT_CARDS_IMPRESSION", 12, "cci");
        p = eVar13;
        e eVar14 = new e("CONTENT_CARDS_CONTROL_IMPRESSION", 13, "ccic");
        q = eVar14;
        e eVar15 = new e("CONTENT_CARDS_DISMISS", 14, "ccd");
        r = eVar15;
        e eVar16 = new e("INCREMENT", 15, "inc");
        s = eVar16;
        e eVar17 = new e("ADD_TO_CUSTOM_ATTRIBUTE_ARRAY", 16, "add");
        t = eVar17;
        e eVar18 = new e("REMOVE_FROM_CUSTOM_ATTRIBUTE_ARRAY", 17, "rem");
        u = eVar18;
        e eVar19 = new e("SET_CUSTOM_ATTRIBUTE_ARRAY", 18, "set");
        v = eVar19;
        e eVar20 = new e("INAPP_MESSAGE_IMPRESSION", 19, "si");
        w = eVar20;
        e eVar21 = new e("INAPP_MESSAGE_CONTROL_IMPRESSION", 20, "iec");
        x = eVar21;
        e eVar22 = new e("INAPP_MESSAGE_CLICK", 21, "sc");
        y = eVar22;
        e eVar23 = new e("INAPP_MESSAGE_BUTTON_CLICK", 22, "sbc");
        z = eVar23;
        e eVar24 = new e("INAPP_MESSAGE_MESSAGE_EXTRAS", 23, "message_extras");
        e eVar25 = new e("USER_ALIAS", 24, "uae");
        A = eVar25;
        e eVar26 = new e("SESSION_START", 25, "ss");
        B = eVar26;
        e eVar27 = new e("SESSION_END", 26, "se");
        C = eVar27;
        e eVar28 = new e("TEST_TYPE", 27, "tt");
        e eVar29 = new e("LOCATION_CUSTOM_ATTRIBUTE_ADD", 28, "lcaa");
        D = eVar29;
        e eVar30 = new e("LOCATION_CUSTOM_ATTRIBUTE_REMOVE", 29, "lcar");
        E = eVar30;
        e eVar31 = new e("NESTED_CUSTOM_ATTRIBUTE_MERGE", 30, "ncam");
        F = eVar31;
        e eVar32 = new e("SUBSCRIPTION_GROUP_UPDATE", 31, "sgu");
        G = eVar32;
        e eVar33 = new e("FEATURE_FLAG_IMPRESSION_EVENT", 32, "ffi");
        H = eVar33;
        e eVar34 = new e("BANNER_IMPRESSION_EVENT", 33, "bi");
        I = eVar34;
        e eVar35 = new e("BANNER_CLICK_EVENT", 34, "bc");
        J = eVar35;
        e eVar36 = new e("PUSH_DELIVERY_EVENT", 35, "pde");
        K = eVar36;
        e eVar37 = new e("UNKNOWN", 36, "");
        L = eVar37;
        e[] eVarArr = {eVar, eVar2, eVar3, eVar4, eVar5, eVar6, eVar7, eVar8, eVar9, eVar10, eVar11, eVar12, eVar13, eVar14, eVar15, eVar16, eVar17, eVar18, eVar19, eVar20, eVar21, eVar22, eVar23, eVar24, eVar25, eVar26, eVar27, eVar28, eVar29, eVar30, eVar31, eVar32, eVar33, eVar34, eVar35, eVar36, eVar37};
        M = eVarArr;
        AbstractC3328d.f(eVarArr);
        b = new d();
        e[] eVarArrValues = values();
        int iA = U.a(eVarArrValues.length);
        LinkedHashMap linkedHashMap = new LinkedHashMap(iA < 16 ? 16 : iA);
        for (e eVar38 : eVarArrValues) {
            linkedHashMap.put(eVar38.a, eVar38);
        }
        c = linkedHashMap;
    }

    public e(String str, int i2, String str2) {
        this.a = str2;
    }

    public static e valueOf(String str) {
        return (e) Enum.valueOf(e.class, str);
    }

    public static e[] values() {
        return (e[]) M.clone();
    }

    @Override // com.braze.models.IPutIntoJson
    public final Object forJsonPut() {
        return this.a;
    }
}

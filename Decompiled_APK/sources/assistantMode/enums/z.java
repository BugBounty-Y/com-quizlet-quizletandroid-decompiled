package assistantMode.enums;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.collections.U;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* loaded from: classes.dex */
public final class z {
    public static final z b;
    public static final z c;
    public static final z d;
    public static final z e;
    public static final z f;
    public static final z g;
    public static final z h;
    public static final z i;
    public static final z j;
    public static final z k;
    public static final z l;
    public static final z m;
    public static final z n;
    public static final z o;
    public static final /* synthetic */ z[] p;
    public final Map a;

    static {
        E[] eArrValues = E.values();
        int iA = U.a(eArrValues.length);
        LinkedHashMap linkedHashMap = new LinkedHashMap(iA < 16 ? 16 : iA);
        for (E e2 : eArrValues) {
            linkedHashMap.put(e2.name(), Integer.valueOf(e2.a));
        }
        b = new z("TERM_SIDE", 0, null, 16);
        k[] kVarArr = {k.b, k.c, k.d, k.e};
        int iA2 = U.a(4);
        LinkedHashMap linkedHashMap2 = new LinkedHashMap(iA2 < 16 ? 16 : iA2);
        for (int i2 = 0; i2 < 4; i2++) {
            k kVar = kVarArr[i2];
            linkedHashMap2.put(A.a(kVar.name()), Integer.valueOf(kVar.a));
        }
        c = new z("TEST_QUESTION_TYPES", 1, linkedHashMap2, 8);
        d = new z("TEST_QUESTION_COUNT", 2, null, 24);
        e = new z("SHUFFLE", 3, null, 24);
        f = new z("INSTANT_FEEDBACK", 4, null, 24);
        g = new z("TAP_TO_PLAY_AUDIO", 5, null, 24);
        h = new z("TEST_SELECTED_ONLY_QUESTION_COUNT", 6, null, 24);
        k[] kVarArr2 = {k.b, k.c, k.d, k.e, k.f, k.g, k.h, k.i, k.j, k.l};
        int iA3 = U.a(10);
        LinkedHashMap linkedHashMap3 = new LinkedHashMap(iA3 < 16 ? 16 : iA3);
        for (int i3 = 0; i3 < 10; i3++) {
            k kVar2 = kVarArr2[i3];
            linkedHashMap3.put(A.a(kVar2.name()), Integer.valueOf(kVar2.a));
        }
        z zVar = new z("ASSISTANT_MODE_QUESTION_TYPES", 7, linkedHashMap3, 8);
        i = zVar;
        z zVar2 = new z("ASSISTANT_MODE_WORD_SIDE", 8, null, 24);
        z zVar3 = new z("ASSISTANT_MODE_DEFINITION_SIDE", 9, null, 24);
        z zVar4 = new z("ASSISTANT_MODE_WRITTEN_WORD_SIDE", 10, null, 24);
        j = zVar4;
        z zVar5 = new z("ASSISTANT_MODE_WRITTEN_DEFINITION_SIDE", 11, null, 24);
        k = zVar5;
        LinkedHashMap linkedHashMap4 = A.a;
        z zVar6 = new z("PROMPT_TERM_SIDES", 12, linkedHashMap4, 8);
        l = zVar6;
        z zVar7 = new z("ANSWER_TERM_SIDES", 13, linkedHashMap4, 8);
        m = zVar7;
        z zVar8 = new z("MATCH_MODE_SIDES", 14, linkedHashMap4, 8);
        z zVar9 = new z("TEST_PROMPT_TERM_SIDES", 15, linkedHashMap4, 8);
        n = zVar9;
        z zVar10 = new z("TEST_ANSWER_TERM_SIDES", 16, linkedHashMap4, 8);
        o = zVar10;
        z[] zVarArr = {b, c, d, e, f, g, h, zVar, zVar2, zVar3, zVar4, zVar5, zVar6, zVar7, zVar8, zVar9, zVar10, new z("TEST_SHOW_IMAGES", 17, null, 24), new z("LIVE_PLAY_MUSIC", 18, null, 24), new z("FLEXIBLE_GRADING_ACCEPT_PARTIAL_ANSWERS", 19, null, 24), new z("FLEXIBLE_GRADING_ACCEPT_ANSWERS_WITH_TYPOS", 20, null, 24)};
        p = zVarArr;
        AbstractC3328d.f(zVarArr);
    }

    public z(String str, int i2, LinkedHashMap linkedHashMap, int i3) {
        this.a = (i3 & 16) != 0 ? null : linkedHashMap;
    }

    public static z valueOf(String str) {
        return (z) Enum.valueOf(z.class, str);
    }

    public static z[] values() {
        return (z[]) p.clone();
    }
}

package com.iabtcf.utils;

import com.google.android.gms.internal.mlkit_vision_document_scanner.C;
import java.util.EnumMap;

/* JADX WARN: Enum visitor error
jadx.core.utils.exceptions.JadxRuntimeException: Init of enum field 'v' uses external variables
	at jadx.core.dex.visitors.EnumVisitor.createEnumFieldByConstructor(EnumVisitor.java:451)
	at jadx.core.dex.visitors.EnumVisitor.processEnumFieldByRegister(EnumVisitor.java:395)
	at jadx.core.dex.visitors.EnumVisitor.extractEnumFieldsFromFilledArray(EnumVisitor.java:324)
	at jadx.core.dex.visitors.EnumVisitor.extractEnumFieldsFromInsn(EnumVisitor.java:262)
	at jadx.core.dex.visitors.EnumVisitor.convertToEnum(EnumVisitor.java:151)
	at jadx.core.dex.visitors.EnumVisitor.visit(EnumVisitor.java:100)
 */
/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* loaded from: classes2.dex */
public final class l {
    public static final l A;
    public static final l B;
    public static final l C;
    public static final l D;
    public static final l E;
    public static final l F;
    public static final l G;
    public static final l H;
    public static final l I;
    public static final l J;
    public static final l K;
    public static final l L;
    public static final l M;
    public static final l V;
    public static final l W;
    public static final l X;
    public static final l Y;
    public static final l Z;
    public static final l c1;
    public static final l d1;
    public static final l e;
    public static final l e1;
    public static final l f;
    public static final l f1;
    public static final l g;
    public static final l g1;
    public static final l h;
    public static final l h1;
    public static final l i;
    public static final l i1;
    public static final l j;
    public static final l j1;
    public static final l k;
    public static final l k1;
    public static final l l;
    public static final l l1;
    public static final l m;
    public static final l m1;
    public static final l n;
    public static final l n1;
    public static final l o;
    public static final l o1;
    public static final l p;
    public static final /* synthetic */ l[] p1;
    public static final l q;
    public static final l r;
    public static final l s;
    public static final l t;
    public static final l u;
    public static final l v;
    public static final l w;
    public static final l x;
    public static final l y;
    public static final l z;
    public final j a;
    public final g b;
    public volatile boolean c;
    public volatile boolean d;

    /* JADX INFO: Fake field, exist only in values array */
    l EF2;

    static {
        l lVar = new l(0, 6, (Object) null, "CORE_VERSION");
        e = lVar;
        l lVar2 = new l("CORE_CREATED", 1, 36);
        f = lVar2;
        l lVar3 = new l("CORE_LAST_UPDATED", 2, 36);
        g = lVar3;
        l lVar4 = new l("CORE_CMP_ID", 3, 12);
        h = lVar4;
        l lVar5 = new l("CORE_CMP_VERSION", 4, 12);
        i = lVar5;
        l lVar6 = new l("CORE_CONSENT_SCREEN", 5, 6);
        j = lVar6;
        l lVar7 = new l("CORE_CONSENT_LANGUAGE", 6, 12);
        k = lVar7;
        l lVar8 = new l("CORE_VENDOR_LIST_VERSION", 7, 12);
        l = lVar8;
        l lVar9 = new l("CORE_TCF_POLICY_VERSION", 8, 6);
        m = lVar9;
        l lVar10 = new l("CORE_IS_SERVICE_SPECIFIC", 9, 1);
        n = lVar10;
        l lVar11 = new l("CORE_USE_NON_STANDARD_STOCKS", 10, 1);
        o = lVar11;
        l lVar12 = new l("CORE_SPECIAL_FEATURE_OPT_INS", 11, 12);
        p = lVar12;
        l lVar13 = new l("CORE_PURPOSES_CONSENT", 12, 24);
        q = lVar13;
        l lVar14 = new l("CORE_PURPOSES_LI_TRANSPARENCY", 13, 24);
        r = lVar14;
        l lVar15 = new l("CORE_PURPOSE_ONE_TREATMENT", 14, 1);
        s = lVar15;
        l lVar16 = new l("CORE_PUBLISHER_CC", 15, 12);
        t = lVar16;
        final l lVar17 = new l("CORE_VENDOR_MAX_VENDOR_ID", 16, 16);
        u = lVar17;
        final l lVar18 = new l("CORE_VENDOR_IS_RANGE_ENCODING", 17, 1);
        l lVar19 = new l("CORE_VENDOR_BITRANGE_FIELD", 18, new g() { // from class: com.iabtcf.utils.e
            @Override // com.iabtcf.utils.g
            public final boolean a() {
                return true;
            }

            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                a aVar = (a) obj;
                int iB = this.b.b(aVar);
                return Integer.valueOf(!aVar.b(iB) ? aVar.f(lVar17.b(aVar)) : C.c(aVar, iB + 1));
            }
        });
        v = lVar19;
        final l lVar20 = new l("CORE_VENDOR_LI_MAX_VENDOR_ID", 19, 16);
        w = lVar20;
        final l lVar21 = new l("CORE_VENDOR_LI_IS_RANGE_ENCODING", 20, 1);
        l lVar22 = new l("CORE_VENDOR_LI_BITRANGE_FIELD", 21, new g() { // from class: com.iabtcf.utils.e
            @Override // com.iabtcf.utils.g
            public final boolean a() {
                return true;
            }

            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                a aVar = (a) obj;
                int iB = this.b.b(aVar);
                return Integer.valueOf(!aVar.b(iB) ? aVar.f(lVar20.b(aVar)) : C.c(aVar, iB + 1));
            }
        });
        x = lVar22;
        final l lVar23 = new l("CORE_NUM_PUB_RESTRICTION", 22, 12);
        y = lVar23;
        l lVar24 = new l("CORE_PUB_RESTRICTION_ENTRY", 23, new g() { // from class: com.iabtcf.utils.k
            @Override // com.iabtcf.utils.g
            public final boolean a() {
                return true;
            }

            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                a aVar = (a) obj;
                int iB = this.b.b(aVar);
                int iD = aVar.d(iB);
                int iA = l.y.a(aVar) + iB;
                for (int i2 = 0; i2 < iD; i2++) {
                    int iA2 = l.X.a(aVar) + l.W.a(aVar) + iA;
                    iA = C.c(aVar, iA2) + iA2;
                }
                return Integer.valueOf(iA - iB);
            }
        });
        z = lVar24;
        l lVar25 = new l(24, 3, (Object) null, "OOB_SEGMENT_TYPE");
        A = lVar25;
        final l lVar26 = new l("DV_MAX_VENDOR_ID", 25, 16, lVar25);
        B = lVar26;
        final l lVar27 = new l("DV_IS_RANGE_ENCODING", 26, 1);
        l lVar28 = new l("DV_VENDOR_BITRANGE_FIELD", 27, new g() { // from class: com.iabtcf.utils.e
            @Override // com.iabtcf.utils.g
            public final boolean a() {
                return true;
            }

            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                a aVar = (a) obj;
                int iB = this.b.b(aVar);
                return Integer.valueOf(!aVar.b(iB) ? aVar.f(lVar26.b(aVar)) : C.c(aVar, iB + 1));
            }
        });
        C = lVar28;
        final l lVar29 = new l("AV_MAX_VENDOR_ID", 28, 16, lVar25);
        D = lVar29;
        final l lVar30 = new l("AV_IS_RANGE_ENCODING", 29, 1);
        l lVar31 = new l("AV_VENDOR_BITRANGE_FIELD", 30, new g() { // from class: com.iabtcf.utils.e
            @Override // com.iabtcf.utils.g
            public final boolean a() {
                return true;
            }

            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                a aVar = (a) obj;
                int iB = this.b.b(aVar);
                return Integer.valueOf(!aVar.b(iB) ? aVar.f(lVar29.b(aVar)) : C.c(aVar, iB + 1));
            }
        });
        E = lVar31;
        l lVar32 = new l(31, 3, (Object) null, "PPTC_SEGMENT_TYPE");
        l lVar33 = new l("PPTC_PUB_PURPOSES_CONSENT", 32, 24);
        F = lVar33;
        l lVar34 = new l("PPTC_PUB_PURPOSES_LI_TRANSPARENCY", 33, 24);
        G = lVar34;
        l lVar35 = new l("PPTC_NUM_CUSTOM_PURPOSES", 34, 6);
        H = lVar35;
        final int i2 = 0;
        l lVar36 = new l("PPTC_CUSTOM_PURPOSES_CONSENT", 35, new g() { // from class: com.iabtcf.utils.d
            @Override // com.iabtcf.utils.g
            public final boolean a() {
                switch (i2) {
                }
                return true;
            }

            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                switch (i2) {
                    case 0:
                        a aVar = (a) obj;
                        return Integer.valueOf(aVar.h(l.H.b(aVar)));
                    case 1:
                        return Integer.valueOf(l.I.a((a) obj));
                    case 2:
                        a aVar2 = (a) obj;
                        return Integer.valueOf(Byte.toUnsignedInt(aVar2.h(l.o1.b(aVar2))));
                    default:
                        a aVar3 = (a) obj;
                        return !aVar3.b(l.k1.b(aVar3)) ? Integer.valueOf(aVar3.f(l.j1.b(aVar3))) : Integer.valueOf(C.c(aVar3, l.n1.b(aVar3)));
                }
            }
        });
        I = lVar36;
        final int i3 = 1;
        l lVar37 = new l("PPTC_CUSTOM_PURPOSES_LI_TRANSPARENCY", 36, new g() { // from class: com.iabtcf.utils.d
            @Override // com.iabtcf.utils.g
            public final boolean a() {
                switch (i3) {
                }
                return true;
            }

            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                switch (i3) {
                    case 0:
                        a aVar = (a) obj;
                        return Integer.valueOf(aVar.h(l.H.b(aVar)));
                    case 1:
                        return Integer.valueOf(l.I.a((a) obj));
                    case 2:
                        a aVar2 = (a) obj;
                        return Integer.valueOf(Byte.toUnsignedInt(aVar2.h(l.o1.b(aVar2))));
                    default:
                        a aVar3 = (a) obj;
                        return !aVar3.b(l.k1.b(aVar3)) ? Integer.valueOf(aVar3.f(l.j1.b(aVar3))) : Integer.valueOf(C.c(aVar3, l.n1.b(aVar3)));
                }
            }
        });
        J = lVar37;
        l lVar38 = new l("NUM_ENTRIES", 37, 12, 0);
        K = lVar38;
        l lVar39 = new l("IS_A_RANGE", 38, 1, 0);
        L = lVar39;
        l lVar40 = new l("START_OR_ONLY_VENDOR_ID", 39, 16, 0);
        M = lVar40;
        l lVar41 = new l("END_VENDOR_ID", 40, 16, 0);
        V = lVar41;
        l lVar42 = new l("TIMESTAMP", 41, 36, 0);
        l lVar43 = new l("PURPOSE_ID", 42, 6, 0);
        W = lVar43;
        l lVar44 = new l("RESTRICTION_TYPE", 43, 2, 0);
        X = lVar44;
        l lVar45 = new l("CHAR", 44, 6, 0);
        l lVar46 = new l(45, 6, (Object) null, "V1_VERSION");
        Y = lVar46;
        l lVar47 = new l("V1_CREATED", 46, 36);
        Z = lVar47;
        l lVar48 = new l("V1_LAST_UPDATED", 47, 36);
        c1 = lVar48;
        l lVar49 = new l("V1_CMP_ID", 48, 12);
        d1 = lVar49;
        l lVar50 = new l("V1_CMP_VERSION", 49, 12);
        e1 = lVar50;
        l lVar51 = new l("V1_CONSENT_SCREEN", 50, 6);
        f1 = lVar51;
        l lVar52 = new l("V1_CONSENT_LANGUAGE", 51, 12);
        g1 = lVar52;
        l lVar53 = new l("V1_VENDOR_LIST_VERSION", 52, 12);
        h1 = lVar53;
        l lVar54 = new l("V1_PURPOSES_ALLOW", 53, 24);
        i1 = lVar54;
        l lVar55 = new l("V1_VENDOR_MAX_VENDOR_ID", 54, 16);
        j1 = lVar55;
        l lVar56 = new l("V1_VENDOR_IS_RANGE_ENCODING", 55, 1);
        k1 = lVar56;
        final int i4 = 3;
        l lVar57 = new l("V1_VENDOR_BITRANGE_FIELD", 56, new g() { // from class: com.iabtcf.utils.d
            @Override // com.iabtcf.utils.g
            public final boolean a() {
                switch (i4) {
                }
                return true;
            }

            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                switch (i4) {
                    case 0:
                        a aVar = (a) obj;
                        return Integer.valueOf(aVar.h(l.H.b(aVar)));
                    case 1:
                        return Integer.valueOf(l.I.a((a) obj));
                    case 2:
                        a aVar2 = (a) obj;
                        return Integer.valueOf(Byte.toUnsignedInt(aVar2.h(l.o1.b(aVar2))));
                    default:
                        a aVar3 = (a) obj;
                        return !aVar3.b(l.k1.b(aVar3)) ? Integer.valueOf(aVar3.f(l.j1.b(aVar3))) : Integer.valueOf(C.c(aVar3, l.n1.b(aVar3)));
                }
            }
        });
        l1 = lVar57;
        l lVar58 = new l("V1_VENDOR_DEFAULT_CONSENT", 57, 1, lVar56);
        m1 = lVar58;
        l lVar59 = new l("V1_VENDOR_NUM_ENTRIES", 58, 12);
        n1 = lVar59;
        l lVar60 = new l("V1_PPC_PUBLISHER_PURPOSES_VERSION", 59, 12, lVar53);
        l lVar61 = new l("V1_PPC_STANDARD_PURPOSES_ALLOWED", 60, 24);
        l lVar62 = new l("V1_PPC_NUMBER_CUSTOM_PURPOSES", 61, 6);
        o1 = lVar62;
        final int i5 = 2;
        p1 = new l[]{lVar, lVar2, lVar3, lVar4, lVar5, lVar6, lVar7, lVar8, lVar9, lVar10, lVar11, lVar12, lVar13, lVar14, lVar15, lVar16, lVar17, lVar18, lVar19, lVar20, lVar21, lVar22, lVar23, lVar24, lVar25, lVar26, lVar27, lVar28, lVar29, lVar30, lVar31, lVar32, lVar33, lVar34, lVar35, lVar36, lVar37, lVar38, lVar39, lVar40, lVar41, lVar42, lVar43, lVar44, lVar45, lVar46, lVar47, lVar48, lVar49, lVar50, lVar51, lVar52, lVar53, lVar54, lVar55, lVar56, lVar57, lVar58, lVar59, lVar60, lVar61, lVar62, new l("V1_PPC_CUSTOM_PURPOSES_BITFIELD", 62, new g() { // from class: com.iabtcf.utils.d
            @Override // com.iabtcf.utils.g
            public final boolean a() {
                switch (i5) {
                }
                return true;
            }

            @Override // java.util.function.Function
            public final Object apply(Object obj) {
                switch (i5) {
                    case 0:
                        a aVar = (a) obj;
                        return Integer.valueOf(aVar.h(l.H.b(aVar)));
                    case 1:
                        return Integer.valueOf(l.I.a((a) obj));
                    case 2:
                        a aVar2 = (a) obj;
                        return Integer.valueOf(Byte.toUnsignedInt(aVar2.h(l.o1.b(aVar2))));
                    default:
                        a aVar3 = (a) obj;
                        return !aVar3.b(l.k1.b(aVar3)) ? Integer.valueOf(aVar3.f(l.j1.b(aVar3))) : Integer.valueOf(C.c(aVar3, l.n1.b(aVar3)));
                }
            }
        })};
    }

    public l(String str, int i2, int i3, l lVar) {
        this.c = false;
        this.d = false;
        this.b = new f(i3);
        this.a = new i(lVar, 0);
    }

    public static l valueOf(String str) {
        return (l) Enum.valueOf(l.class, str);
    }

    public static l[] values() {
        return (l[]) p1.clone();
    }

    public final int a(a aVar) {
        com.quizlet.data.repository.folderwithcreator.e eVar = aVar.c;
        return eVar.o(this, (EnumMap) eVar.c, this.b).intValue();
    }

    public final int b(a aVar) {
        com.quizlet.data.repository.folderwithcreator.e eVar = aVar.c;
        return eVar.o(this, (EnumMap) eVar.d, this.a).intValue();
    }

    public final boolean c() {
        if (!this.d) {
            this.c = this.a.a() || this.b.a();
            this.d = true;
        }
        return this.c;
    }

    public l(String str, int i2, int i3, int i4) {
        h hVar = j.a;
        this.c = false;
        this.d = false;
        this.b = new f(i3);
        this.a = hVar;
    }

    public l(int i2, int i3, Object obj, String str) {
        this.c = false;
        this.d = false;
        this.b = new f(i3);
        this.a = new h(1);
    }

    public l(String str, int i2, g gVar) {
        this.c = false;
        this.d = false;
        this.b = gVar;
        this.a = new i(this, 1);
    }

    public l(String str, int i2, int i3) {
        this.c = false;
        this.d = false;
        this.b = new f(i3);
        this.a = new i(this, 1);
    }
}

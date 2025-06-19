package com.perimeterx.mobile_sdk.doctor_app.model;

import kotlin.A;
import kotlin.jvm.internal.Intrinsics;
import kotlin.z;

/* loaded from: classes2.dex */
public final class f {
    public final g a;
    public final d b;

    public f(g type, d summary) {
        Intrinsics.checkNotNullParameter(type, "type");
        Intrinsics.checkNotNullParameter(summary, "summary");
        this.a = type;
        this.b = summary;
    }

    public static h a(boolean z) {
        return z ? h.a : h.b;
    }

    public final boolean b() {
        int iOrdinal = this.a.ordinal();
        return iOrdinal == 1 || iOrdinal == 4 || iOrdinal == 15;
    }

    public final boolean c(int i) {
        int iOrdinal;
        g.a.getClass();
        if (com.quizlet.shared.usecase.folderstudymaterials.b.a(i) != null && ((iOrdinal = this.a.ordinal()) == 2 || iOrdinal == 5 || iOrdinal == 11 || iOrdinal == 16 || iOrdinal == 19)) {
            return false;
        }
        z zVar = A.b;
        g type = com.quizlet.shared.usecase.folderstudymaterials.b.a(i - 1);
        if (type == null) {
            return false;
        }
        Intrinsics.checkNotNullParameter(type, "type");
        d summary = this.b;
        Intrinsics.checkNotNullParameter(summary, "summary");
        h hVarE = new f(type, summary).e();
        return hVarE == h.b || hVarE == h.c;
    }

    public final boolean d(g gVar) {
        if (this.b.e == null) {
            return true;
        }
        A a = gVar.a();
        Intrinsics.d(a);
        return c(a.a);
    }

    public final h e() {
        if (b()) {
            return null;
        }
        g gVar = this.a;
        int iOrdinal = gVar.ordinal();
        d dVar = this.b;
        switch (iOrdinal) {
            case 5:
                b bVar = dVar.e;
                if (bVar == null) {
                    break;
                } else {
                    break;
                }
            case 6:
                if (!d(gVar)) {
                    b bVar2 = dVar.e;
                    Intrinsics.d(bVar2);
                    break;
                } else {
                    break;
                }
            case 7:
                if (!d(gVar)) {
                    b bVar3 = dVar.e;
                    Intrinsics.d(bVar3);
                    break;
                } else {
                    break;
                }
            case 8:
                if (!d(gVar)) {
                    b bVar4 = dVar.e;
                    Intrinsics.d(bVar4);
                    break;
                } else {
                    break;
                }
            case 9:
                if (!d(gVar)) {
                    b bVar5 = dVar.e;
                    Intrinsics.d(bVar5);
                    break;
                } else {
                    break;
                }
            case 10:
                if (!d(gVar)) {
                    b bVar6 = dVar.e;
                    Intrinsics.d(bVar6);
                    break;
                } else {
                    break;
                }
            case 11:
                if (!d(gVar)) {
                    b bVar7 = dVar.e;
                    Intrinsics.d(bVar7);
                    break;
                } else {
                    break;
                }
            case 12:
                if (!d(gVar)) {
                    b bVar8 = dVar.e;
                    Intrinsics.d(bVar8);
                    break;
                } else {
                    break;
                }
            case 13:
                if (!d(gVar)) {
                    b bVar9 = dVar.e;
                    Intrinsics.d(bVar9);
                    break;
                } else {
                    break;
                }
            case 14:
                if (!d(gVar)) {
                    b bVar10 = dVar.e;
                    if (bVar10 != null && bVar10.j) {
                        break;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
                break;
            case 16:
                if (!f(gVar)) {
                    i iVar = dVar.f;
                    Intrinsics.d(iVar);
                    break;
                } else {
                    break;
                }
            case 17:
                if (!f(gVar)) {
                    i iVar2 = dVar.f;
                    Intrinsics.d(iVar2);
                    break;
                } else {
                    break;
                }
            case 18:
                if (!f(gVar)) {
                    i iVar3 = dVar.f;
                    Intrinsics.d(iVar3);
                    break;
                } else {
                    break;
                }
            case 19:
                if (!f(gVar)) {
                    i iVar4 = dVar.f;
                    Intrinsics.d(iVar4);
                    break;
                } else {
                    break;
                }
        }
        return null;
    }

    public final boolean f(g gVar) {
        if (this.b.f == null) {
            return true;
        }
        A a = gVar.a();
        Intrinsics.d(a);
        return c(a.a);
    }
}

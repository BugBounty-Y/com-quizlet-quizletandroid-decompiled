package org.wordpress.aztec.toolbar;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import java.util.Set;
import kotlin.collections.C4933y;
import kotlin.collections.Z;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.x;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class d implements c {
    public static final d c;
    public static final /* synthetic */ d[] d;
    public final e a;
    public final Set b;

    static {
        e eVar = e.a;
        d dVar = new d("BACKGROUND", 0, eVar, Z.b(x.G));
        e eVar2 = e.e;
        x xVar = x.a;
        d dVar2 = new d("ADD_MEDIA_COLLAPSE", 1, eVar2, Z.b(xVar));
        d dVar3 = new d("ADD_MEDIA_EXPAND", 2, eVar2, Z.b(xVar));
        e eVar3 = e.d;
        d dVar4 = new d("HEADING", 3, eVar3, Z.b(xVar));
        e eVar4 = e.c;
        d dVar5 = new d("LIST", 4, eVar4, Z.b(xVar));
        d dVar6 = new d("HIGHLIGHT", 5, eVar, Z.b(x.I));
        d dVar7 = new d("UNORDERED_LIST", 6, eVar4, Z.b(x.h));
        d dVar8 = new d("ORDERED_LIST", 7, eVar4, Z.b(x.i));
        d dVar9 = new d("TASK_LIST", 8, eVar4, Z.b(x.j));
        d dVar10 = new d("INDENT", 9, eVar2, Z.b(xVar));
        d dVar11 = new d("OUTDENT", 10, eVar2, Z.b(xVar));
        x[] elements = {x.l, x.k};
        Intrinsics.checkNotNullParameter(elements, "elements");
        d dVar12 = new d("BOLD", 11, eVar, C4933y.T(elements));
        c = dVar12;
        x[] elements2 = {x.n, x.m};
        Intrinsics.checkNotNullParameter(elements2, "elements");
        d[] dVarArr = {dVar, dVar2, dVar3, dVar4, dVar5, dVar6, dVar7, dVar8, dVar9, dVar10, dVar11, dVar12, new d("ITALIC", 12, eVar, C4933y.T(elements2)), new d("STRIKETHROUGH", 13, eVar, Z.b(x.q)), new d("ALIGN_LEFT", 14, eVar4, Z.b(x.r)), new d("ALIGN_CENTER", 15, eVar4, Z.b(x.s)), new d("ALIGN_RIGHT", 16, eVar4, Z.b(x.t)), new d("UNDERLINE", 17, eVar, Z.b(x.p)), new d("QUOTE", 18, eVar4, Z.b(x.u)), new d("LINK", 19, eVar2, Z.b(x.v)), new d("CODE", 20, e.b, Z.b(x.F)), new d("PREFORMAT", 21, eVar4, Z.b(x.y)), new d("HORIZONTAL_RULE", 22, eVar3, Z.b(x.w)), new d("HTML", 23, eVar2, Z.b(xVar)), new d("ELLIPSIS_COLLAPSE", 24, eVar2, Z.b(xVar)), new d("ELLIPSIS_EXPAND", 25, eVar2, Z.b(xVar))};
        d = dVarArr;
        AbstractC3328d.f(dVarArr);
    }

    public d(String str, int i, e eVar, Set set) {
        this.a = eVar;
        this.b = set;
    }

    public static d valueOf(String str) {
        return (d) Enum.valueOf(d.class, str);
    }

    public static d[] values() {
        return (d[]) d.clone();
    }

    @Override // org.wordpress.aztec.toolbar.c
    public final boolean a() {
        return this.a != e.e;
    }

    @Override // org.wordpress.aztec.toolbar.c
    public final Set b() {
        return this.b;
    }
}

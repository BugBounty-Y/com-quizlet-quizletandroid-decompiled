package com.quizlet.richtext.ui.toolbar;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.quizlet.quizletandroid.R;
import java.util.Set;
import kotlin.collections.C4933y;
import kotlin.collections.Z;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.toolbar.e;
import org.wordpress.aztec.x;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class c implements org.wordpress.aztec.toolbar.c {
    public static final c c;
    public static final c d;
    public static final c e;
    public static final c f;
    public static final c g;
    public static final c h;
    public static final /* synthetic */ c[] i;
    public final int a;
    public final Set b;

    static {
        e eVar = e.a;
        x[] elements = {x.l, x.k};
        Intrinsics.checkNotNullParameter(elements, "elements");
        c cVar = new c("BOLD", 0, R.id.buttonBold, C4933y.T(elements));
        c = cVar;
        x[] elements2 = {x.n, x.m};
        Intrinsics.checkNotNullParameter(elements2, "elements");
        c cVar2 = new c("ITALIC", 1, R.id.buttonItalic, C4933y.T(elements2));
        d = cVar2;
        c cVar3 = new c("UNDERLINE", 2, R.id.buttonUnderline, Z.b(x.p));
        e = cVar3;
        x xVar = x.G;
        c cVar4 = new c("BG_BLUE", 3, R.id.buttonBgBlue, Z.b(xVar));
        f = cVar4;
        c cVar5 = new c("BG_PINK", 4, R.id.buttonBgPink, Z.b(xVar));
        g = cVar5;
        c cVar6 = new c("BG_YELLOW", 5, R.id.buttonBgYellow, Z.b(xVar));
        h = cVar6;
        c[] cVarArr = {cVar, cVar2, cVar3, cVar4, cVar5, cVar6};
        i = cVarArr;
        AbstractC3328d.f(cVarArr);
    }

    public c(String str, int i2, int i3, Set set) {
        e eVar = e.a;
        this.a = i3;
        this.b = set;
    }

    public static c valueOf(String str) {
        return (c) Enum.valueOf(c.class, str);
    }

    public static c[] values() {
        return (c[]) i.clone();
    }

    @Override // org.wordpress.aztec.toolbar.c
    public final boolean a() {
        e eVar = e.a;
        e eVar2 = e.a;
        return true;
    }

    @Override // org.wordpress.aztec.toolbar.c
    public final Set b() {
        return this.b;
    }
}

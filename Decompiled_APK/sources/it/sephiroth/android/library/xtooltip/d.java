package it.sephiroth.android.library.xtooltip;

import android.content.Context;
import android.graphics.Point;
import android.graphics.Typeface;
import android.view.View;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class d {
    public Point a;
    public a b;
    public String c;
    public View d;
    public int e;
    public int f;
    public Typeface g;
    public boolean h;
    public final Context i;

    public d(@NotNull Context context) {
        Intrinsics.f(context, "context");
        this.i = context;
        this.b = a.b;
        this.e = R.style.ToolTipLayoutDefaultStyle;
        this.f = R.attr.ttlm_defaultStyle;
        this.h = true;
    }
}

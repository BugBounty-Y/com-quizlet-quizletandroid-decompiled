package androidx.compose.ui.text.android;

import android.os.Build;
import android.text.StaticLayout;
import com.skydoves.balloon.internals.DefinitionKt;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class o implements t {
    @Override // androidx.compose.ui.text.android.t
    @NotNull
    public StaticLayout a(@NotNull u uVar) {
        StaticLayout.Builder builderObtain = StaticLayout.Builder.obtain(uVar.a, 0, uVar.b, uVar.c, uVar.d);
        builderObtain.setTextDirection(uVar.e);
        builderObtain.setAlignment(uVar.f);
        builderObtain.setMaxLines(uVar.g);
        builderObtain.setEllipsize(uVar.h);
        builderObtain.setEllipsizedWidth(uVar.i);
        builderObtain.setLineSpacing(DefinitionKt.NO_Float_VALUE, 1.0f);
        builderObtain.setIncludePad(uVar.k);
        builderObtain.setBreakStrategy(uVar.l);
        builderObtain.setHyphenationFrequency(uVar.o);
        builderObtain.setIndents(null, null);
        int i = Build.VERSION.SDK_INT;
        p.a(builderObtain, uVar.j);
        if (i >= 28) {
            q.a(builderObtain, true);
        }
        if (i >= 33) {
            r.b(builderObtain, uVar.m, uVar.n);
        }
        return builderObtain.build();
    }
}

package dagger.hilt.android.internal.lifecycle;

import androidx.activity.s;
import androidx.lifecycle.w0;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.quizlet.quizletandroid.C4622e;
import com.quizlet.quizletandroid.ui.joincontenttofolder.i;

/* loaded from: classes3.dex */
public final class f implements y0 {
    public static final i d = new i(5);
    public final dagger.internal.b a;
    public final y0 b;
    public final androidx.lifecycle.viewmodel.d c;

    public f(dagger.internal.b bVar, y0 y0Var, com.quizlet.data.interactor.set.c cVar) {
        this.a = bVar;
        this.b = y0Var;
        this.c = new androidx.lifecycle.viewmodel.d(cVar, 1);
    }

    public static f d(s sVar, y0 y0Var) {
        C4622e c4622e = (C4622e) ((d) K6.b(d.class, sVar));
        return new f(c4622e.c(), y0Var, new com.quizlet.data.interactor.set.c(c4622e.b, c4622e.c));
    }

    @Override // androidx.lifecycle.y0
    public final w0 a(Class cls) {
        if (!this.a.containsKey(cls)) {
            return this.b.a(cls);
        }
        this.c.a(cls);
        throw null;
    }

    @Override // androidx.lifecycle.y0
    public final w0 b(Class cls, androidx.lifecycle.viewmodel.e eVar) {
        return this.a.containsKey(cls) ? this.c.b(cls, eVar) : this.b.b(cls, eVar);
    }
}

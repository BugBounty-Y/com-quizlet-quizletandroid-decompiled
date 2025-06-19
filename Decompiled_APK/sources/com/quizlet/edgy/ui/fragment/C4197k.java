package com.quizlet.edgy.ui.fragment;

import android.content.res.Resources;
import android.text.Editable;
import android.text.TextWatcher;
import androidx.lifecycle.p0;
import com.quizlet.edgy.ui.viewmodel.C4210k;
import java.lang.ref.WeakReference;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.s0;
import kotlinx.coroutines.y0;
import org.wordpress.aztec.AztecText;

/* renamed from: com.quizlet.edgy.ui.fragment.k, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4197k implements TextWatcher {
    public final /* synthetic */ int a;
    public final Object b;
    public Object c;

    public /* synthetic */ C4197k(com.quizlet.edgy.databinding.b bVar, EdgyAddSchoolAndCoursesFragment edgyAddSchoolAndCoursesFragment, int i) {
        this.a = i;
        this.b = bVar;
        this.c = edgyAddSchoolAndCoursesFragment;
    }

    private final void a(int i, int i2, int i3, CharSequence charSequence) {
    }

    private final void b(int i, int i2, int i3, CharSequence charSequence) {
    }

    private final void c(int i, int i2, int i3, CharSequence charSequence) {
    }

    private final void d(int i, int i2, int i3, CharSequence charSequence) {
    }

    @Override // android.text.TextWatcher
    public final void afterTextChanged(Editable text) throws Resources.NotFoundException {
        s0 s0Var;
        Object value;
        Object obj = this.b;
        switch (this.a) {
            case 0:
                com.quizlet.edgy.databinding.b bVar = (com.quizlet.edgy.databinding.b) obj;
                bVar.i.setEndIconVisible(!(text == null || text.length() == 0));
                if (bVar.h.hasFocus()) {
                    String str = EdgyAddSchoolAndCoursesFragment.u;
                    com.quizlet.edgy.ui.viewmodel.M mU = ((EdgyAddSchoolAndCoursesFragment) this.c).U();
                    String query = String.valueOf(text);
                    mU.getClass();
                    Intrinsics.checkNotNullParameter(query, "query");
                    y0 y0Var = mU.v;
                    if (y0Var != null) {
                        y0Var.j(null);
                    }
                    if (query.length() != 0) {
                        if (!Intrinsics.b(mU.l, query)) {
                            mU.l = query;
                            mU.v = kotlinx.coroutines.E.A(p0.j(mU), mU.u, null, new com.quizlet.edgy.ui.viewmodel.I(mU, query, null), 2);
                            break;
                        }
                    } else {
                        do {
                            s0Var = mU.p;
                            value = s0Var.getValue();
                        } while (!s0Var.k(value, C4210k.a));
                    }
                }
                break;
            case 1:
                com.quizlet.edgy.databinding.b bVar2 = (com.quizlet.edgy.databinding.b) obj;
                bVar2.g.setEndIconVisible(!(text == null || text.length() == 0));
                if (bVar2.f.hasFocus()) {
                    String str2 = EdgyAddSchoolAndCoursesFragment.u;
                    com.quizlet.edgy.ui.viewmodel.M mU2 = ((EdgyAddSchoolAndCoursesFragment) this.c).U();
                    String query2 = String.valueOf(text);
                    mU2.getClass();
                    Intrinsics.checkNotNullParameter(query2, "query");
                    y0 y0Var2 = mU2.w;
                    if (y0Var2 != null) {
                        y0Var2.j(null);
                    }
                    if (query2.length() != 0) {
                        if (!Intrinsics.b(mU2.m, query2)) {
                            mU2.m = query2;
                            mU2.w = kotlinx.coroutines.E.A(p0.j(mU2), mU2.u, null, new com.quizlet.edgy.ui.viewmodel.G(mU2, query2, null), 2);
                            break;
                        }
                    } else {
                        mU2.D();
                        break;
                    }
                }
                break;
            default:
                Intrinsics.checkNotNullParameter(text, "text");
                break;
        }
    }

    @Override // android.text.TextWatcher
    public final void beforeTextChanged(CharSequence text, int i, int i2, int i3) {
        switch (this.a) {
            case 0:
            case 1:
                break;
            default:
                Intrinsics.checkNotNullParameter(text, "text");
                this.c = new org.wordpress.aztec.watchers.h(text.toString(), 6);
                break;
        }
    }

    @Override // android.text.TextWatcher
    public final void onTextChanged(CharSequence text, int i, int i2, int i3) {
        AztecText aztecText;
        switch (this.a) {
            case 0:
            case 1:
                break;
            default:
                Intrinsics.checkNotNullParameter(text, "text");
                org.wordpress.aztec.watchers.h hVar = (org.wordpress.aztec.watchers.h) this.c;
                hVar.d = i2;
                Intrinsics.checkNotNullParameter(text, "<set-?>");
                hVar.c = text;
                org.wordpress.aztec.watchers.h hVar2 = (org.wordpress.aztec.watchers.h) this.c;
                hVar2.f = i3;
                hVar2.e = i;
                hVar2.a();
                if (!((org.wordpress.aztec.watchers.h) this.c).b() && (aztecText = (AztecText) ((WeakReference) this.b).get()) != null && text.length() == 0) {
                    org.wordpress.aztec.watchers.h hVar3 = (org.wordpress.aztec.watchers.h) this.c;
                    if (hVar3.g == 0 && hVar3.l == 1) {
                        aztecText.n = true;
                        break;
                    }
                }
                break;
        }
    }

    public C4197k(AztecText aztecText) {
        this.a = 2;
        Intrinsics.checkNotNullParameter(aztecText, "aztecText");
        this.b = new WeakReference(aztecText);
        this.c = new org.wordpress.aztec.watchers.h();
    }
}

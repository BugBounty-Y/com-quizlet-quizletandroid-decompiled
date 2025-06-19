package androidx.activity;

import android.window.OnBackInvokedDispatcher;
import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.activity.h, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C0036h implements androidx.lifecycle.H {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ C0036h(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // androidx.lifecycle.H
    public final void d(androidx.lifecycle.J j, androidx.lifecycle.A event) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(j, "<anonymous parameter 0>");
                Intrinsics.checkNotNullParameter(event, "event");
                if (event == androidx.lifecycle.A.ON_CREATE) {
                    OnBackInvokedDispatcher invoker = AbstractC0037i.a((s) this.c);
                    L l = (L) this.b;
                    l.getClass();
                    Intrinsics.checkNotNullParameter(invoker, "invoker");
                    l.e = invoker;
                    l.d(l.g);
                    break;
                }
                break;
            case 1:
                if (event == ((androidx.lifecycle.A) this.b)) {
                    ((Function0) ((InterfaceC0773a0) this.c).getValue()).invoke();
                    break;
                }
                break;
            default:
                Intrinsics.checkNotNullParameter(j, "<unused var>");
                Intrinsics.checkNotNullParameter(event, "event");
                int i = com.quizlet.features.questiontypes.composables.e.a[event.ordinal()];
                if (i == 1) {
                    ((Function0) this.b).invoke();
                    break;
                } else if (i == 2) {
                    ((Function0) this.c).invoke();
                    break;
                }
                break;
        }
    }
}

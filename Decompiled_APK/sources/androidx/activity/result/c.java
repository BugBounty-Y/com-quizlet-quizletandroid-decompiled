package androidx.activity.result;

import android.os.Bundle;
import androidx.compose.animation.core.C0238e;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.lifecycle.A;
import androidx.lifecycle.H;
import androidx.lifecycle.J;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3197l6;
import com.quizlet.assembly.compose.buttons.b0;
import com.quizlet.assembly.compose.buttons.d0;
import java.util.LinkedHashMap;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

/* loaded from: classes.dex */
public final /* synthetic */ class c implements H {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    public /* synthetic */ c(Object obj, Object obj2, Object obj3, Object obj4, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
        this.e = obj4;
    }

    @Override // androidx.lifecycle.H
    public final void d(J j, A event) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(j, "<anonymous parameter 0>");
                Intrinsics.checkNotNullParameter(event, "event");
                A a = A.ON_START;
                h hVar = (h) this.b;
                String str = (String) this.c;
                if (a != event) {
                    if (A.ON_STOP != event) {
                        if (A.ON_DESTROY == event) {
                            hVar.f(str);
                            break;
                        }
                    } else {
                        hVar.e.remove(str);
                        break;
                    }
                } else {
                    LinkedHashMap linkedHashMap = hVar.e;
                    a aVar = (a) this.d;
                    androidx.activity.result.contract.a aVar2 = (androidx.activity.result.contract.a) this.e;
                    linkedHashMap.put(str, new d(aVar2, aVar));
                    LinkedHashMap linkedHashMap2 = hVar.f;
                    if (linkedHashMap2.containsKey(str)) {
                        Object obj = linkedHashMap2.get(str);
                        linkedHashMap2.remove(str);
                        aVar.a(obj);
                    }
                    Bundle bundle = hVar.g;
                    ActivityResult activityResult = (ActivityResult) AbstractC3197l6.a(bundle, str);
                    if (activityResult != null) {
                        bundle.remove(str);
                        aVar.a(aVar2.c(activityResult.a, activityResult.b));
                        break;
                    }
                }
                break;
            default:
                Intrinsics.checkNotNullParameter(j, "<unused var>");
                Intrinsics.checkNotNullParameter(event, "event");
                if (d0.a[event.ordinal()] == 1) {
                    E.A(p0.h((J) this.b), null, null, new b0((Function1) this.c, (C0238e) this.d, (InterfaceC0773a0) this.e, null), 3);
                    break;
                }
                break;
        }
    }
}

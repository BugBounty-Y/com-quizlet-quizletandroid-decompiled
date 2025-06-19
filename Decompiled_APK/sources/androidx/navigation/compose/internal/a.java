package androidx.navigation.compose.internal;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.navigation.H;
import androidx.navigation.r;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3634h5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.a7;
import com.quizlet.features.settings.composables.navigation.j;
import com.quizlet.features.settings.composables.navigation.k;
import com.quizlet.features.settings.composables.navigation.n;
import com.quizlet.features.settings.composables.navigation.o;
import com.quizlet.features.settings.composables.navigation.p;
import com.quizlet.features.settings.composables.navigation.q;
import com.quizlet.features.settings.composables.navigation.t;
import com.quizlet.features.settings.composables.navigation.u;
import com.quizlet.features.settings.composables.w;
import com.quizlet.features.settings.data.models.b;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class a implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Object c;

    public /* synthetic */ a(H h, boolean z) {
        this.a = 1;
        this.c = h;
        this.b = z;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                R1.d(this.b, (Function2) this.c, (InterfaceC0806l) obj, C0776c.H(1));
                return Unit.a;
            case 1:
                b bVar = (b) obj;
                String authToken = (String) obj2;
                Intrinsics.checkNotNullParameter(authToken, "authToken");
                int i = bVar == null ? -1 : w.a[bVar.ordinal()];
                if (i != -1) {
                    H h = (H) this.c;
                    boolean z = this.b;
                    if (i == 1) {
                        r.d(h, (z ? o.a : n.a).b(authToken));
                    } else if (i == 2) {
                        r.d(h, (z ? u.a : t.a).b(authToken));
                    } else if (i == 3) {
                        r.d(h, (z ? k.a : j.a).e());
                    } else {
                        if (i != 4) {
                            throw new NoWhenBranchMatchedException();
                        }
                        r.d(h, (z ? q.a : p.a).b(authToken));
                    }
                }
                return Unit.a;
            case 2:
                ((Integer) obj2).getClass();
                AbstractC3634h5.h((String) this.c, this.b, (InterfaceC0806l) obj, C0776c.H(1));
                return Unit.a;
            default:
                ((Integer) obj2).getClass();
                a7.a(this.b, (androidx.compose.ui.n) this.c, (InterfaceC0806l) obj, C0776c.H(1));
                return Unit.a;
        }
    }

    public /* synthetic */ a(String str, int i, boolean z) {
        this.a = 2;
        this.c = str;
        this.b = z;
    }

    public /* synthetic */ a(boolean z, Object obj, int i, int i2) {
        this.a = i2;
        this.b = z;
        this.c = obj;
    }
}

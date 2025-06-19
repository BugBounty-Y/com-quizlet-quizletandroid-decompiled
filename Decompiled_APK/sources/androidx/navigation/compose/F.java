package androidx.navigation.compose;

import androidx.compose.foundation.pager.C0466e;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0853m;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3189k7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3215n6;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.google.android.gms.internal.mlkit_vision_camera.Q1;
import com.google.android.gms.internal.mlkit_vision_camera.T1;
import com.google.android.gms.internal.mlkit_vision_camera.k3;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3496m4;
import com.quizlet.data.model.SimpleImage;
import com.quizlet.generated.enums.y1;
import com.quizlet.studiablemodels.StudiableAudio;
import java.io.Serializable;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final /* synthetic */ class F implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ int c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;

    public /* synthetic */ F(int i, com.quizlet.features.setpage.studypreview.g gVar, C0466e c0466e, kotlinx.collections.immutable.e eVar, androidx.compose.runtime.snapshots.q qVar, int i2) {
        this.a = 8;
        this.b = i;
        this.d = gVar;
        this.e = c0466e;
        this.f = eVar;
        this.g = qVar;
        this.c = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.b | 1);
                String str = (String) this.e;
                Function1 function1 = (Function1) this.g;
                Q1.d((androidx.navigation.H) this.d, str, (androidx.compose.ui.q) this.f, function1, (InterfaceC0806l) obj, iH, this.c);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.b | 1);
                com.quizlet.explanations.solution.fragments.b bVar = (com.quizlet.explanations.solution.fragments.b) this.e;
                C0853m c0853m = (C0853m) this.g;
                com.quizlet.explanations.solution.recyclerview.step.i.d((SimpleImage) this.d, bVar, (com.quizlet.explanations.solution.recyclerview.step.b) this.f, c0853m, (InterfaceC0806l) obj, iH2, this.c);
                break;
            case 2:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(this.b | 1);
                String str2 = (String) this.e;
                androidx.compose.ui.text.L l = (androidx.compose.ui.text.L) this.g;
                com.facebook.appevents.m.j(str2, (androidx.compose.ui.q) this.f, (Integer) this.d, l, (InterfaceC0806l) obj, iH3, this.c);
                break;
            case 3:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(this.c | 1);
                androidx.compose.runtime.internal.d dVar = (androidx.compose.runtime.internal.d) this.f;
                Q4.a((com.quizlet.ui.models.content.listitem.o) this.d, this.b, (Function1) this.g, (androidx.compose.foundation.lazy.A) this.e, dVar, (InterfaceC0806l) obj, iH4);
                break;
            case 4:
                ((Integer) obj2).getClass();
                int iH5 = C0776c.H(this.b | 1);
                com.quizlet.features.infra.folder.menu.viewmodel.n nVar = (com.quizlet.features.infra.folder.menu.viewmodel.n) this.g;
                AbstractC3215n6.f((y1) this.d, (String) this.e, (com.quizlet.features.infra.folder.save.viewmodel.c) this.f, nVar, (InterfaceC0806l) obj, iH5, this.c);
                break;
            case 5:
                ((Integer) obj2).getClass();
                int iH6 = C0776c.H(this.b | 1);
                Function0 function0 = (Function0) this.g;
                AbstractC3189k7.b((String) this.e, (androidx.compose.ui.q) this.f, (String) this.d, function0, (InterfaceC0806l) obj, iH6, this.c);
                break;
            case 6:
                ((Integer) obj2).getClass();
                int iH7 = C0776c.H(this.b | 1);
                androidx.compose.ui.q qVar = (androidx.compose.ui.q) this.f;
                T1.d((String) this.e, (androidx.compose.ui.graphics.painter.b) this.d, (Function0) this.g, qVar, (InterfaceC0806l) obj, iH7, this.c);
                break;
            case 7:
                ((Integer) obj2).getClass();
                int iH8 = C0776c.H(this.b | 1);
                Function1 function12 = (Function1) this.g;
                k3.a((androidx.compose.ui.q) this.f, (StudiableAudio) this.d, (Function0) this.e, function12, (InterfaceC0806l) obj, iH8, this.c);
                break;
            case 8:
                ((Integer) obj2).getClass();
                int iH9 = C0776c.H(this.c | 1);
                kotlinx.collections.immutable.e eVar = (kotlinx.collections.immutable.e) this.f;
                androidx.compose.runtime.snapshots.q qVar2 = (androidx.compose.runtime.snapshots.q) this.g;
                com.google.android.gms.internal.mlkit_vision_common.B.a(this.b, (com.quizlet.features.setpage.studypreview.g) this.d, (C0466e) this.e, eVar, qVar2, (InterfaceC0806l) obj, iH9);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH10 = C0776c.H(this.b | 1);
                com.quizlet.features.userprofile.ui.a aVar = (com.quizlet.features.userprofile.ui.a) this.d;
                Function0 function02 = (Function0) this.g;
                AbstractC3496m4.a(aVar, (androidx.compose.ui.q) this.f, (androidx.compose.runtime.internal.d) this.e, function02, (InterfaceC0806l) obj, iH10, this.c);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ F(androidx.compose.ui.q qVar, StudiableAudio studiableAudio, Function0 function0, Function1 function1, int i, int i2) {
        this.a = 7;
        this.f = qVar;
        this.d = studiableAudio;
        this.e = function0;
        this.g = function1;
        this.b = i;
        this.c = i2;
    }

    public /* synthetic */ F(com.quizlet.features.userprofile.ui.a aVar, androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar, Function0 function0, int i, int i2) {
        this.a = 9;
        this.d = aVar;
        this.f = qVar;
        this.e = dVar;
        this.g = function0;
        this.b = i;
        this.c = i2;
    }

    public /* synthetic */ F(com.quizlet.ui.models.content.listitem.o oVar, int i, Function1 function1, androidx.compose.foundation.lazy.A a, androidx.compose.runtime.internal.d dVar, int i2) {
        this.a = 3;
        this.d = oVar;
        this.b = i;
        this.g = function1;
        this.e = a;
        this.f = dVar;
        this.c = i2;
    }

    public /* synthetic */ F(Object obj, Serializable serializable, Object obj2, Object obj3, int i, int i2, int i3) {
        this.a = i3;
        this.d = obj;
        this.e = serializable;
        this.f = obj2;
        this.g = obj3;
        this.b = i;
        this.c = i2;
    }

    public /* synthetic */ F(String str, androidx.compose.ui.q qVar, Object obj, Object obj2, int i, int i2, int i3) {
        this.a = i3;
        this.e = str;
        this.f = qVar;
        this.d = obj;
        this.g = obj2;
        this.b = i;
        this.c = i2;
    }

    public /* synthetic */ F(String str, androidx.compose.ui.graphics.painter.b bVar, Function0 function0, androidx.compose.ui.q qVar, int i, int i2) {
        this.a = 6;
        this.e = str;
        this.d = bVar;
        this.g = function0;
        this.f = qVar;
        this.b = i;
        this.c = i2;
    }
}

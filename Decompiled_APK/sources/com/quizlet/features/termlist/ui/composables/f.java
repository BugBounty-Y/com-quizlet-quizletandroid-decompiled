package com.quizlet.features.termlist.ui.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_common.K3;
import com.google.android.gms.internal.mlkit_vision_common.L3;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class f implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ long b;
    public final /* synthetic */ q c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ String e;
    public final /* synthetic */ int f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ InterfaceC4938g h;

    public /* synthetic */ f(long j, boolean z, String str, String str2, q qVar, kotlin.jvm.functions.d dVar, int i) {
        this.b = j;
        this.d = z;
        this.e = str;
        this.g = str2;
        this.c = qVar;
        this.h = dVar;
        this.f = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.f | 1);
                q qVar = this.c;
                kotlin.jvm.functions.d dVar = (kotlin.jvm.functions.d) this.h;
                K3.b(this.b, this.d, this.e, (String) this.g, qVar, dVar, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.f | 1);
                String str = this.e;
                kotlin.jvm.functions.c cVar = (kotlin.jvm.functions.c) this.h;
                L3.a((com.quizlet.features.infra.models.a) this.g, this.b, this.c, this.d, str, cVar, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ f(com.quizlet.features.infra.models.a aVar, long j, q qVar, boolean z, String str, kotlin.jvm.functions.c cVar, int i) {
        this.g = aVar;
        this.b = j;
        this.c = qVar;
        this.d = z;
        this.e = str;
        this.h = cVar;
        this.f = i;
    }
}

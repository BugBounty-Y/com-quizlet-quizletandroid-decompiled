package com.quizlet.features.achievements.ui.composables;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_camera.o3;
import com.quizlet.studiablemodels.StudiableAudio;
import com.quizlet.studiablemodels.StudiableImage;
import com.quizlet.studiablemodels.StudiableText;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.features.achievements.ui.composables.f, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C4219f implements Function2 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ int b;
    public final /* synthetic */ androidx.compose.ui.q c;
    public final /* synthetic */ Function0 d;
    public final /* synthetic */ int e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ Object h;
    public final /* synthetic */ Object i;
    public final /* synthetic */ Object j;

    public /* synthetic */ C4219f(int i, StudiableText studiableText, StudiableImage studiableImage, StudiableAudio studiableAudio, androidx.compose.ui.q qVar, Function0 function0, Function1 function1, Function1 function12, int i2) {
        this.b = i;
        this.f = studiableText;
        this.g = studiableImage;
        this.h = studiableAudio;
        this.c = qVar;
        this.d = function0;
        this.i = function1;
        this.j = function12;
        this.e = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.e | 1);
                String str = (String) this.g;
                String str2 = (String) this.h;
                String str3 = (String) this.i;
                Integer num = (Integer) this.j;
                Function0 function0 = this.d;
                com.facebook.appevents.m.f(this.b, (kotlinx.collections.immutable.b) this.f, str, str2, str3, this.c, num, function0, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.e | 1);
                Function1 function1 = (Function1) this.i;
                Function1 function12 = (Function1) this.j;
                o3.b(this.b, (StudiableText) this.f, (StudiableImage) this.g, (StudiableAudio) this.h, this.c, this.d, function1, function12, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ C4219f(int i, kotlinx.collections.immutable.b bVar, String str, String str2, String str3, androidx.compose.ui.q qVar, Integer num, Function0 function0, int i2) {
        this.b = i;
        this.f = bVar;
        this.g = str;
        this.h = str2;
        this.i = str3;
        this.c = qVar;
        this.j = num;
        this.d = function0;
        this.e = i2;
    }
}

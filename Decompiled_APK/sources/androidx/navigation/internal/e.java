package androidx.navigation.internal;

import android.os.Bundle;
import androidx.compose.animation.core.C0238e;
import androidx.compose.animation.core.P;
import androidx.compose.foundation.text.C0486e0;
import androidx.compose.runtime.H;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.ui.focus.p;
import androidx.compose.ui.platform.C0957n0;
import androidx.compose.ui.platform.Q0;
import androidx.lifecycle.J;
import androidx.lifecycle.u0;
import androidx.navigation.B;
import androidx.navigation.C1291m;
import androidx.navigation.E;
import com.google.android.gms.internal.mlkit_vision_barcode.N5;
import com.quizlet.data.model.B2;
import com.quizlet.data.model.C2;
import com.quizlet.eventlogger.model.NotesEventLog;
import com.quizlet.features.folders.composables.AbstractC4249e;
import com.quizlet.features.folders.composables.a0;
import com.quizlet.features.folders.data.U;
import com.quizlet.features.folders.data.U0;
import com.quizlet.features.folders.data.V0;
import com.quizlet.features.folders.data.W0;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.LearnSettingsIntentData;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.G;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.t;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import java.nio.ByteBuffer;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.F;
import kotlin.jvm.internal.Intrinsics;
import okio.InterfaceC5093j;

/* loaded from: classes.dex */
public final /* synthetic */ class e implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    public /* synthetic */ e(Object obj, Object obj2, Object obj3, Object obj4, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
        this.e = obj4;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        int i = 14;
        Object obj2 = null;
        int i2 = 2;
        Object obj3 = this.d;
        Object obj4 = this.b;
        Object obj5 = this.e;
        Object obj6 = this.c;
        switch (this.a) {
            case 0:
                C1291m it2 = (C1291m) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                ((F) obj4).a = true;
                ((j) obj6).a((B) obj3, (Bundle) obj5, it2, K.a);
                return Unit.a;
            case 1:
                H DisposableEffect = (H) obj;
                Intrinsics.checkNotNullParameter(DisposableEffect, "$this$DisposableEffect");
                J j = (J) obj4;
                androidx.activity.result.c cVar = new androidx.activity.result.c(j, (Function1) obj6, (C0238e) obj3, (InterfaceC0773a0) obj5, 1);
                j.getLifecycle().a(cVar);
                return new P(14, j, cVar);
            case 2:
                H DisposableEffect2 = (H) obj;
                Intrinsics.checkNotNullParameter(DisposableEffect2, "$this$DisposableEffect");
                com.quizlet.diagrams.ui.g gVar = new com.quizlet.diagrams.ui.g((com.quizlet.diagrams.ui.i) obj6, (DiagramData) obj3, (com.quizlet.diagrams.b[]) obj5);
                J j2 = (J) obj4;
                j2.getLifecycle().a(gVar);
                return new P(15, j2, gVar);
            case 3:
                H DisposableEffect3 = (H) obj;
                Intrinsics.checkNotNullParameter(DisposableEffect3, "$this$DisposableEffect");
                com.facebook.login.B b = (com.facebook.login.B) obj4;
                com.facebook.j jVar = (com.facebook.j) obj6;
                b.f(jVar, new androidx.work.impl.model.c((Function1) obj3, new u0(19, (Object) b, obj5)));
                return new androidx.activity.compose.c(b, jVar);
            case 4:
                androidx.compose.foundation.lazy.g LazyColumn = (androidx.compose.foundation.lazy.g) obj;
                Intrinsics.checkNotNullParameter(LazyColumn, "$this$LazyColumn");
                androidx.compose.foundation.lazy.g.s(LazyColumn, AbstractC4249e.b);
                U u = (U) obj4;
                Function1 function1 = (Function1) obj5;
                androidx.compose.foundation.lazy.g.p(LazyColumn, u.a.a, new androidx.compose.runtime.internal.d(true, 53270569, new a0(u, function1, 0)), 2);
                W0 w0 = (W0) obj6;
                if (w0 instanceof U0) {
                    androidx.compose.foundation.lazy.g.p(LazyColumn, null, AbstractC4249e.c, 3);
                    androidx.compose.foundation.lazy.g.s(LazyColumn, new androidx.compose.runtime.internal.d(true, 25410318, new com.quizlet.assembly.compose.input.m(11, w0, function1)));
                } else {
                    if (!Intrinsics.b(w0, V0.a)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    androidx.compose.foundation.lazy.g.p(LazyColumn, null, AbstractC4249e.d, 3);
                }
                ((Function1) obj3).invoke(LazyColumn);
                return Unit.a;
            case 5:
                NotesEventLog.Payload createEvent = (NotesEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setNoteUuid((String) obj4);
                Integer num = (Integer) obj6;
                if (num != null) {
                    createEvent.setCharCount(Integer.valueOf(num.intValue()));
                }
                createEvent.setFileTypes((List) obj3);
                createEvent.setInputType((String) obj5);
                return Unit.a;
            case 6:
                C0486e0 KeyboardActions = (C0486e0) obj;
                Intrinsics.checkNotNullParameter(KeyboardActions, "$this$KeyboardActions");
                Q0 q0 = (Q0) obj4;
                if (q0 != null) {
                    ((C0957n0) q0).a();
                }
                ((p) obj6).c();
                ((Function1) obj3).invoke((String) ((InterfaceC0773a0) obj5).getValue());
                return Unit.a;
            case 7:
                E NavHost = (E) obj;
                Intrinsics.checkNotNullParameter(NavHost, "$this$NavHost");
                androidx.navigation.H h = (androidx.navigation.H) obj3;
                N5.d(NavHost, new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation.d((LearnSettingsIntentData) obj4), new androidx.compose.runtime.internal.d(true, 814612680, new com.quizlet.features.questiontypes.mcq.ui.c(13, (Function1) obj6, h)));
                N5.d(NavHost, com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation.e.a, new androidx.compose.runtime.internal.d(true, -99753359, new com.quizlet.features.questiontypes.mcq.ui.c(i, h, (com.quizlet.quizletandroid.ui.navigationmanagers.c) obj5)));
                return Unit.a;
            case 8:
                H DisposableEffect4 = (H) obj;
                Intrinsics.checkNotNullParameter(DisposableEffect4, "$this$DisposableEffect");
                com.quizlet.features.flashcards.screens.c cVar2 = new com.quizlet.features.flashcards.screens.c((G) obj6, (androidx.lifecycle.E) obj3, (t) obj5, i2);
                J j3 = (J) obj4;
                j3.getLifecycle().a(cVar2);
                return new P(22, j3, cVar2);
            case 9:
                androidx.glance.appwidget.lazy.h LazyColumn2 = (androidx.glance.appwidget.lazy.h) obj;
                Intrinsics.checkNotNullParameter(LazyColumn2, "$this$LazyColumn");
                androidx.appcompat.view.a aVar = (androidx.appcompat.view.a) obj5;
                LazyColumn2.a(Long.MIN_VALUE, new androidx.compose.runtime.internal.d(true, 1908206811, new com.quizlet.quizletandroid.ui.widgets.E((C2) obj6, (B2) obj3, aVar)));
                List list = (List) obj4;
                LazyColumn2.b(list.size(), new com.quizlet.assembly.compose.menu.e(list, 24), new androidx.compose.runtime.internal.d(true, -1405343893, new com.quizlet.features.practicetest.common.composables.k(list, aVar, i2)));
                LazyColumn2.a(Long.MIN_VALUE, com.quizlet.quizletandroid.ui.widgets.l.a);
                return Unit.a;
            default:
                CoroutineContext coroutineContext = (CoroutineContext) obj5;
                try {
                    ((kotlin.jvm.internal.H) obj4).a = ((InterfaceC5093j) obj6).read((ByteBuffer) obj);
                    return Unit.a;
                } finally {
                }
        }
    }
}

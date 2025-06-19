package androidx.navigation.compose;

import android.content.Context;
import android.content.Intent;
import android.content.IntentSender;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3162h7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3171i7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3173j0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3182k0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3215n6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3269u0;
import com.google.android.gms.internal.mlkit_vision_barcode.C5;
import com.google.android.gms.internal.mlkit_vision_barcode.G4;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3327c2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3339f2;
import com.google.android.gms.internal.mlkit_vision_camera.G1;
import com.google.android.gms.internal.mlkit_vision_camera.K1;
import com.google.android.gms.internal.mlkit_vision_camera.L1;
import com.google.android.gms.internal.mlkit_vision_camera.M1;
import com.google.android.gms.internal.mlkit_vision_camera.O1;
import com.google.android.gms.internal.mlkit_vision_camera.Q1;
import com.google.android.gms.internal.mlkit_vision_camera.W1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3603d6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3745v5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.B5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.T4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.r7;
import com.quizlet.data.model.C4114c;
import com.quizlet.data.model.EssayItem;
import com.quizlet.data.model.J1;
import com.quizlet.data.model.R0;
import com.quizlet.data.model.V0;
import com.quizlet.features.folders.data.Q0;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import com.quizlet.features.questionnaire.navigation.Control;
import com.quizlet.features.setpage.shareset.ShareIntentSender;
import com.quizlet.quizletandroid.R;
import com.quizlet.utm.a;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.navigation.compose.m, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C1280m implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ C1280m(com.quizlet.features.notes.manager.a aVar, Object obj, int i) {
        this.a = i;
        this.b = aVar;
        this.c = obj;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        Object obj3 = this.c;
        Object obj4 = this.b;
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                L1.b((androidx.compose.runtime.snapshots.q) obj4, (List) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 1:
                ((Integer) obj2).getClass();
                androidx.compose.runtime.saveable.f fVar = (androidx.compose.runtime.saveable.f) obj4;
                M1.b(fVar, (androidx.compose.runtime.internal.d) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 2:
                ((Integer) obj2).getClass();
                T4.g((kotlinx.collections.immutable.e) obj4, (androidx.compose.ui.q) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 3:
                ((Integer) obj2).getClass();
                AbstractC3745v5.j((com.quizlet.assembly.compose.input.w) obj4, (Function0) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 4:
                ((Integer) obj2).getClass();
                androidx.compose.ui.n nVar = (androidx.compose.ui.n) obj4;
                B5.h(nVar, (androidx.compose.runtime.internal.d) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 5:
                ((Integer) obj2).getClass();
                AbstractC3603d6.a((com.quizlet.assembly.widgets.progress.c) obj4, (androidx.compose.ui.n) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 6:
                ((Integer) obj2).getClass();
                com.quizlet.explanations.questiondetail.recyclerview.k.b((com.quizlet.explanations.questiondetail.recyclerview.g) obj4, (androidx.compose.ui.n) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 7:
                ((Integer) obj2).getClass();
                r7.a((com.quizlet.explanations.questiondetail.data.e) obj4, (androidx.compose.ui.q) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 8:
                ((Integer) obj2).getClass();
                com.bumptech.glide.c.b((C4114c) obj4, (androidx.compose.ui.n) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 9:
                ((Integer) obj2).getClass();
                com.google.android.exoplayer2.drm.b.e((com.quizlet.data.model.L1) obj4, (androidx.compose.ui.q) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 10:
                ((Integer) obj2).getClass();
                com.google.android.exoplayer2.drm.b.c((J1) obj4, (androidx.compose.ui.q) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 11:
                ((Integer) obj2).getClass();
                com.google.android.gms.common.wrappers.a.b((com.quizlet.features.achievements.data.h) obj4, (Function1) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 12:
                ((Integer) obj2).getClass();
                AbstractC3173j0.f((com.quizlet.features.infra.ui.feedback.sound.soundeffect.e) obj4, (com.google.android.gms.internal.ads.N) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 13:
                ((Integer) obj2).getClass();
                AbstractC3182k0.e((com.quizlet.assembly.widgets.progress.d) obj4, (androidx.compose.ui.n) obj3, (InterfaceC0806l) obj, C0776c.H(9));
                break;
            case 14:
                ((Integer) obj2).getClass();
                AbstractC3269u0.a((com.quizlet.features.flashcards.helpers.a) obj4, (androidx.compose.ui.q) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 15:
                ((Integer) obj2).getClass();
                G4.c(C0776c.H(1), (InterfaceC0806l) obj, (Q0) obj3, (Function1) obj4);
                break;
            case 16:
                ((Integer) obj2).getClass();
                C5.a((com.quizlet.features.infra.compatibility.a) obj4, (androidx.compose.ui.q) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 17:
                ((Integer) obj2).getClass();
                AbstractC3215n6.e((com.quizlet.features.infra.folder.save.screenstates.a) obj4, (Function0) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 18:
                ((Integer) obj2).getClass();
                AbstractC3162h7.a((EssayItem) obj4, (androidx.compose.ui.q) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 19:
                ((Integer) obj2).getClass();
                AbstractC3171i7.b((Function0) obj4, (com.quizlet.features.notes.detail.viewmodels.d) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 20:
                String title = (String) obj;
                com.quizlet.features.notes.data.z data = (com.quizlet.features.notes.data.z) obj2;
                Intrinsics.checkNotNullParameter(title, "title");
                Intrinsics.checkNotNullParameter(data, "data");
                String text = ((Context) obj3).getString(R.string.magic_notes_detail_share_note_text, title, data.c);
                Intrinsics.checkNotNullExpressionValue(text, "getString(...)");
                com.quizlet.quizletandroid.ui.navigationmanagers.e eVar = (com.quizlet.quizletandroid.ui.navigationmanagers.e) ((com.quizlet.features.notes.manager.a) obj4);
                eVar.getClass();
                Intrinsics.checkNotNullParameter(text, "text");
                Intrinsics.checkNotNullParameter(data, "data");
                int i = ShareIntentSender.d;
                a.C0023a c0023aA = data.a.a();
                String str = data.b;
                IntentSender intentSenderA = com.quizlet.features.setpage.shareset.c.a(eVar.a, data.c, null, 20, c0023aA, str);
                Intent intent = new Intent();
                intent.setAction("android.intent.action.SEND");
                intent.putExtra("android.intent.extra.TEXT", text);
                intent.setType("text/plain");
                Intent intentCreateChooser = Intent.createChooser(intent, null, intentSenderA);
                Intrinsics.d(intentCreateChooser);
                eVar.b(intentCreateChooser);
                break;
            case 21:
                com.quizlet.quizletandroid.ui.navigationmanagers.e eVar2 = (com.quizlet.quizletandroid.ui.navigationmanagers.e) ((com.quizlet.features.notes.manager.a) obj4);
                eVar2.getClass();
                com.quizlet.quizletandroid.ui.navigationmanagers.e.a(eVar2, ((Long) obj).longValue(), null, Boolean.TRUE, (AddMaterialFolderData) obj2, 6);
                ((Function0) obj3).invoke();
                break;
            case EventType.WINDOW_STATE /* 22 */:
                ((Integer) obj2).getClass();
                G1.a((com.quizlet.features.onboarding.survey.n) obj4, (Function0) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case EventType.AUDIO /* 23 */:
                ((Integer) obj2).getClass();
                K1.b((com.quizlet.features.paywall.state.c) obj4, (androidx.compose.ui.q) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case EventType.VIDEO /* 24 */:
                ((Integer) obj2).getClass();
                O1.a((R0) obj4, (androidx.compose.ui.q) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case EventType.SUBS /* 25 */:
                ((Integer) obj2).getClass();
                Q1.f((com.quizlet.features.practicetest.common.data.i) obj4, (Function1) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case EventType.CDN /* 26 */:
                ((Integer) obj2).getClass();
                W1.F((com.quizlet.features.practicetest.detail.data.F) obj4, (Function1) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 27:
                ((Integer) obj2).getClass();
                AbstractC3327c2.a((Function1) obj4, (V0) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            case 28:
                ((Integer) obj2).getClass();
                AbstractC3339f2.c((com.quizlet.features.practicetest.results.data.u) obj4, (Function1) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
            default:
                ((Integer) obj2).getClass();
                com.quizlet.features.questionnaire.options.b.a((Control.Button) obj4, (androidx.compose.ui.q) obj3, (InterfaceC0806l) obj, C0776c.H(1));
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ C1280m(Object obj, Object obj2, int i, int i2) {
        this.a = i2;
        this.b = obj;
        this.c = obj2;
    }
}

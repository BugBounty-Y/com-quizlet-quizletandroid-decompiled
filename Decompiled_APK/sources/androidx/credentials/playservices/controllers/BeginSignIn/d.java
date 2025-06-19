package androidx.credentials.playservices.controllers.BeginSignIn;

import android.content.Context;
import androidx.compose.foundation.C0367i0;
import androidx.credentials.exceptions.GetCredentialException;
import androidx.credentials.exceptions.GetCredentialUnknownException;
import androidx.credentials.exceptions.GetCredentialUnsupportedException;
import androidx.credentials.p;
import androidx.credentials.playservices.controllers.GetSignInIntent.CredentialProviderGetSignInIntentController;
import androidx.glance.session.C1227e;
import androidx.glance.session.s;
import androidx.lifecycle.C0;
import androidx.lifecycle.InterfaceC1261w;
import androidx.lifecycle.y0;
import androidx.work.impl.WorkDatabase;
import androidx.work.impl.constraints.trackers.e;
import androidx.work.impl.i;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.quizlet.edgy.ui.fragment.EdgyAddCourseManuallyFragment;
import com.quizlet.edgy.ui.fragment.EdgyAddSchoolManuallyFragment;
import com.quizlet.edgy.ui.fragment.EdgyModalFragment;
import com.quizlet.explanations.feedback.ui.fragments.ExplanationsFeedbackFragment;
import com.quizlet.explanations.textbook.chaptermenu.ui.ChapterMenuFragment;
import com.quizlet.explanations.textbook.ui.TextbookFragment;
import com.quizlet.features.achievements.ui.AchievementsFragment;
import com.quizlet.features.infra.folder.create.CreateFolderModalFragment;
import com.quizlet.features.setpage.terms.ui.SelectedTermsModeFragment;
import com.quizlet.login.recovery.forgotpassword.ui.ForgotPasswordDialogFragment;
import com.quizlet.quizletandroid.ui.activitycenter.fragments.ActivityCenterFragment;
import java.util.LinkedHashSet;
import java.util.UUID;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;
import kotlin.jvm.internal.r;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import okio.x;

/* loaded from: classes.dex */
public final class d extends r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ d(int i, Object obj, Object obj2) {
        super(0);
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    /* JADX WARN: Type inference failed for: r0v104, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v109, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v116, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v127, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v132, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v139, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v146, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v58, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v65, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v72, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v79, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v86, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v93, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r1v4, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        androidx.sqlite.db.framework.b bVarI;
        InterfaceC1261w interfaceC1261w;
        y0 defaultViewModelProviderFactory;
        y0 defaultViewModelProviderFactory2;
        y0 defaultViewModelProviderFactory3;
        y0 defaultViewModelProviderFactory4;
        y0 defaultViewModelProviderFactory5;
        y0 defaultViewModelProviderFactory6;
        y0 defaultViewModelProviderFactory7;
        y0 defaultViewModelProviderFactory8;
        y0 defaultViewModelProviderFactory9;
        y0 defaultViewModelProviderFactory10;
        y0 defaultViewModelProviderFactory11;
        int i = 3;
        int i2 = 1;
        switch (this.a) {
            case 0:
                CredentialProviderBeginSignInController credentialProviderBeginSignInController = (CredentialProviderBeginSignInController) this.b;
                credentialProviderBeginSignInController.g().execute(new androidx.activity.r(28, credentialProviderBeginSignInController, (J) this.c));
                return Unit.a;
            case 1:
                CredentialProviderBeginSignInController credentialProviderBeginSignInController2 = (CredentialProviderBeginSignInController) this.b;
                credentialProviderBeginSignInController2.g().execute(new b(credentialProviderBeginSignInController2, (GetCredentialException) this.c, i2));
                return Unit.a;
            case 2:
                CredentialProviderBeginSignInController credentialProviderBeginSignInController3 = (CredentialProviderBeginSignInController) this.b;
                credentialProviderBeginSignInController3.g().execute(new androidx.activity.r(29, credentialProviderBeginSignInController3, (GetCredentialUnknownException) this.c));
                return Unit.a;
            case 3:
                ((r) this.b).invoke(((J) this.c).a);
                return Unit.a;
            case 4:
                CredentialProviderGetSignInIntentController credentialProviderGetSignInIntentController = (CredentialProviderGetSignInIntentController) this.b;
                credentialProviderGetSignInIntentController.h().execute(new androidx.credentials.playservices.controllers.c(i2, credentialProviderGetSignInIntentController, (p) this.c));
                return Unit.a;
            case 5:
                CredentialProviderGetSignInIntentController credentialProviderGetSignInIntentController2 = (CredentialProviderGetSignInIntentController) this.b;
                credentialProviderGetSignInIntentController2.h().execute(new androidx.credentials.playservices.controllers.c(2, credentialProviderGetSignInIntentController2, (J) this.c));
                return Unit.a;
            case 6:
                CredentialProviderGetSignInIntentController credentialProviderGetSignInIntentController3 = (CredentialProviderGetSignInIntentController) this.b;
                credentialProviderGetSignInIntentController3.h().execute(new androidx.credentials.playservices.controllers.GetSignInIntent.b(credentialProviderGetSignInIntentController3, (GetCredentialException) this.c, 1));
                return Unit.a;
            case 7:
                CredentialProviderGetSignInIntentController credentialProviderGetSignInIntentController4 = (CredentialProviderGetSignInIntentController) this.b;
                credentialProviderGetSignInIntentController4.h().execute(new androidx.credentials.playservices.controllers.c(i, credentialProviderGetSignInIntentController4, (GetCredentialUnknownException) this.c));
                return Unit.a;
            case 8:
                CredentialProviderGetSignInIntentController credentialProviderGetSignInIntentController5 = (CredentialProviderGetSignInIntentController) this.b;
                credentialProviderGetSignInIntentController5.h().execute(new androidx.credentials.playservices.controllers.c(4, credentialProviderGetSignInIntentController5, (GetCredentialUnsupportedException) this.c));
                return Unit.a;
            case 9:
                String str = x.b;
                Context applicationContext = (Context) this.b;
                Intrinsics.checkNotNullExpressionValue(applicationContext, "applicationContext");
                String absolutePath = K6.a(applicationContext, ((androidx.datastore.b) this.c).b).getAbsolutePath();
                Intrinsics.checkNotNullExpressionValue(absolutePath, "applicationContext.dataS…le(fileName).absolutePath");
                return com.quizlet.quizletandroid.ui.folder.logging.a.f(absolutePath, false);
            case 10:
                Context applicationContext2 = (Context) this.b;
                Intrinsics.checkNotNullExpressionValue(applicationContext2, "applicationContext");
                return P6.d(applicationContext2, ((androidx.datastore.b) this.c).b);
            case 11:
                E.A((C) this.b, null, null, new C1227e((s) this.c, null), 3);
                return Unit.a;
            case 12:
                e eVar = ((androidx.work.impl.constraints.controllers.c) this.b).a;
                androidx.work.impl.constraints.controllers.a listener = (androidx.work.impl.constraints.controllers.a) this.c;
                eVar.getClass();
                Intrinsics.checkNotNullParameter(listener, "listener");
                synchronized (eVar.c) {
                    if (((LinkedHashSet) eVar.e).remove(listener) && ((LinkedHashSet) eVar.e).isEmpty()) {
                        eVar.f();
                    }
                }
                return Unit.a;
            case 13:
                androidx.work.impl.r rVar = (androidx.work.impl.r) this.b;
                WorkDatabase workDatabase = rVar.c;
                Intrinsics.checkNotNullExpressionValue(workDatabase, "workManagerImpl.workDatabase");
                workDatabase.o(new androidx.credentials.playservices.controllers.c(9, rVar, (UUID) this.c));
                i.b(rVar.b, rVar.c, rVar.e);
                return Unit.a;
            case 14:
                return ((C0367i0) this.b).invoke((WorkDatabase) this.c);
            case 15:
                androidx.sqlite.db.e eVar2 = ((app.cash.sqldelight.driver.android.i) this.b).a;
                if (eVar2 != null && (bVarI = eVar2.I()) != null) {
                    return bVarI;
                }
                androidx.sqlite.db.framework.b bVar = (androidx.sqlite.db.framework.b) this.c;
                Intrinsics.d(bVar);
                return bVar;
            case 16:
                return new app.cash.sqldelight.driver.android.b(((app.cash.sqldelight.driver.android.i) this.b).i().f((String) this.c));
            case 17:
                C0 c0 = (C0) this.c.getValue();
                interfaceC1261w = c0 instanceof InterfaceC1261w ? (InterfaceC1261w) c0 : null;
                return (interfaceC1261w == null || (defaultViewModelProviderFactory = interfaceC1261w.getDefaultViewModelProviderFactory()) == null) ? ((EdgyAddCourseManuallyFragment) this.b).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory;
            case 18:
                C0 c02 = (C0) this.c.getValue();
                interfaceC1261w = c02 instanceof InterfaceC1261w ? (InterfaceC1261w) c02 : null;
                return (interfaceC1261w == null || (defaultViewModelProviderFactory2 = interfaceC1261w.getDefaultViewModelProviderFactory()) == null) ? ((EdgyAddSchoolManuallyFragment) this.b).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory2;
            case 19:
                C0 c03 = (C0) this.c.getValue();
                interfaceC1261w = c03 instanceof InterfaceC1261w ? (InterfaceC1261w) c03 : null;
                return (interfaceC1261w == null || (defaultViewModelProviderFactory3 = interfaceC1261w.getDefaultViewModelProviderFactory()) == null) ? ((EdgyModalFragment) this.b).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory3;
            case 20:
                C0 c04 = (C0) this.c.getValue();
                interfaceC1261w = c04 instanceof InterfaceC1261w ? (InterfaceC1261w) c04 : null;
                return (interfaceC1261w == null || (defaultViewModelProviderFactory4 = interfaceC1261w.getDefaultViewModelProviderFactory()) == null) ? ((ExplanationsFeedbackFragment) this.b).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory4;
            case 21:
                C0 c05 = (C0) this.c.getValue();
                interfaceC1261w = c05 instanceof InterfaceC1261w ? (InterfaceC1261w) c05 : null;
                return (interfaceC1261w == null || (defaultViewModelProviderFactory5 = interfaceC1261w.getDefaultViewModelProviderFactory()) == null) ? ((ChapterMenuFragment) this.b).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory5;
            case EventType.WINDOW_STATE /* 22 */:
                C0 c06 = (C0) this.c.getValue();
                interfaceC1261w = c06 instanceof InterfaceC1261w ? (InterfaceC1261w) c06 : null;
                return (interfaceC1261w == null || (defaultViewModelProviderFactory6 = interfaceC1261w.getDefaultViewModelProviderFactory()) == null) ? ((TextbookFragment) this.b).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory6;
            case EventType.AUDIO /* 23 */:
                androidx.lifecycle.viewmodel.c cVar = (androidx.lifecycle.viewmodel.c) ((com.quizlet.features.achievements.ui.c) this.b).invoke();
                if (cVar != null) {
                    return cVar;
                }
                C0 c07 = (C0) this.c.getValue();
                interfaceC1261w = c07 instanceof InterfaceC1261w ? (InterfaceC1261w) c07 : null;
                return interfaceC1261w != null ? interfaceC1261w.getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b;
            case EventType.VIDEO /* 24 */:
                C0 c08 = (C0) this.c.getValue();
                interfaceC1261w = c08 instanceof InterfaceC1261w ? (InterfaceC1261w) c08 : null;
                return (interfaceC1261w == null || (defaultViewModelProviderFactory7 = interfaceC1261w.getDefaultViewModelProviderFactory()) == null) ? ((AchievementsFragment) this.b).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory7;
            case EventType.SUBS /* 25 */:
                C0 c09 = (C0) this.c.getValue();
                interfaceC1261w = c09 instanceof InterfaceC1261w ? (InterfaceC1261w) c09 : null;
                return (interfaceC1261w == null || (defaultViewModelProviderFactory8 = interfaceC1261w.getDefaultViewModelProviderFactory()) == null) ? ((CreateFolderModalFragment) this.b).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory8;
            case EventType.CDN /* 26 */:
                androidx.lifecycle.viewmodel.c cVar2 = (androidx.lifecycle.viewmodel.c) ((com.quizlet.featuregate.growthbook.a) this.b).invoke();
                if (cVar2 != null) {
                    return cVar2;
                }
                C0 c010 = (C0) this.c.getValue();
                interfaceC1261w = c010 instanceof InterfaceC1261w ? (InterfaceC1261w) c010 : null;
                return interfaceC1261w != null ? interfaceC1261w.getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b;
            case 27:
                C0 c011 = (C0) this.c.getValue();
                interfaceC1261w = c011 instanceof InterfaceC1261w ? (InterfaceC1261w) c011 : null;
                return (interfaceC1261w == null || (defaultViewModelProviderFactory9 = interfaceC1261w.getDefaultViewModelProviderFactory()) == null) ? ((SelectedTermsModeFragment) this.b).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory9;
            case 28:
                C0 c012 = (C0) this.c.getValue();
                interfaceC1261w = c012 instanceof InterfaceC1261w ? (InterfaceC1261w) c012 : null;
                return (interfaceC1261w == null || (defaultViewModelProviderFactory10 = interfaceC1261w.getDefaultViewModelProviderFactory()) == null) ? ((ForgotPasswordDialogFragment) this.b).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory10;
            default:
                C0 c013 = (C0) this.c.getValue();
                interfaceC1261w = c013 instanceof InterfaceC1261w ? (InterfaceC1261w) c013 : null;
                return (interfaceC1261w == null || (defaultViewModelProviderFactory11 = interfaceC1261w.getDefaultViewModelProviderFactory()) == null) ? ((ActivityCenterFragment) this.b).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory11;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public d(Function1 function1, J j) {
        super(0);
        this.a = 3;
        this.b = (r) function1;
        this.c = j;
    }
}

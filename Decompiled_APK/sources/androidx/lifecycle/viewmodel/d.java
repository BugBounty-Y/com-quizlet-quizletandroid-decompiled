package androidx.lifecycle.viewmodel;

import androidx.activity.s;
import androidx.appcompat.widget.C0122z;
import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_barcode.L6;
import com.google.android.gms.internal.mlkit_vision_camera.C1;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3502n4;
import com.google.common.collect.C;
import com.quizlet.quizletandroid.C4624g;
import com.quizlet.quizletandroid.u;
import com.quizlet.quizletandroid.z;
import dagger.hilt.android.internal.lifecycle.h;
import java.util.Arrays;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

/* loaded from: classes.dex */
public final class d implements y0 {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ d(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // androidx.lifecycle.y0
    public final w0 b(Class modelClass, e extras) {
        w0 w0Var;
        f fVar;
        Function1 function1;
        w0 w0Var2;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(modelClass, "modelClass");
                Intrinsics.checkNotNullParameter(extras, "extras");
                Intrinsics.checkNotNullParameter(modelClass, "<this>");
                C4950i modelClass2 = K.a(modelClass);
                f[] fVarArr = (f[]) this.b;
                f[] initializers = (f[]) Arrays.copyOf(fVarArr, fVarArr.length);
                Intrinsics.checkNotNullParameter(modelClass2, "modelClass");
                Intrinsics.checkNotNullParameter(extras, "extras");
                Intrinsics.checkNotNullParameter(initializers, "initializers");
                int length = initializers.length;
                int i = 0;
                while (true) {
                    w0Var = null;
                    if (i < length) {
                        fVar = initializers[i];
                        if (!fVar.a.equals(modelClass2)) {
                            i++;
                        }
                    } else {
                        fVar = null;
                    }
                }
                if (fVar != null && (function1 = fVar.b) != null) {
                    w0Var = (w0) function1.invoke(extras);
                }
                if (w0Var != null) {
                    return w0Var;
                }
                throw new IllegalArgumentException(("No initializer set for given class " + C1.b(modelClass2)).toString());
            case 1:
                h hVar = new h();
                com.quizlet.data.interactor.set.c cVar = (com.quizlet.data.interactor.set.c) this.b;
                cVar.c = p0.c(extras);
                z zVar = new z((u) cVar.a, (C4624g) cVar.b, (m0) cVar.c);
                z zVar2 = (z) ((dagger.hilt.android.internal.lifecycle.e) K6.b(dagger.hilt.android.internal.lifecycle.e.class, zVar));
                zVar2.getClass();
                AbstractC3502n4.i(142, "expectedSize");
                C0122z c0122z = new C0122z(142);
                c0122z.u("com.quizlet.quizletandroid.ui.login.accountrecovery.signupduplicate.e", zVar2.d);
                c0122z.u("com.quizlet.features.achievements.home.a", zVar2.f);
                c0122z.u("com.quizlet.features.achievements.notification.f", zVar2.g);
                c0122z.u("com.quizlet.features.achievements.viewmodel.b", zVar2.h);
                c0122z.u("com.quizlet.quizletandroid.ui.activitycenter.viewmodels.a", zVar2.i);
                c0122z.u("com.quizlet.features.folders.addtofolder.viewmodel.m", zVar2.j);
                c0122z.u("com.quizlet.quizletandroid.ui.setpage.addset.c", zVar2.k);
                c0122z.u("com.quizlet.features.infra.folder.menu.viewmodel.a", zVar2.l);
                c0122z.u("com.quizlet.ads.viewmodel.a", zVar2.m);
                c0122z.u("com.quizlet.features.settings.viewmodels.b", zVar2.o);
                c0122z.u("com.quizlet.features.settings.viewmodels.d", zVar2.p);
                c0122z.u("com.quizlet.quizletandroid.ui.usersettings.viewmodels.c", zVar2.q);
                c0122z.u("com.quizlet.features.folders.changetags.viewmodel.d", zVar2.r);
                c0122z.u("com.quizlet.features.settings.viewmodels.g", zVar2.s);
                c0122z.u("com.quizlet.explanations.textbook.chaptermenu.viewmodel.b", zVar2.t);
                c0122z.u("com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.a", zVar2.u);
                c0122z.u("com.quizlet.quizletandroid.ui.classcreation.i", zVar2.v);
                c0122z.u("com.quizlet.quizletandroid.ui.group.classuser.viewmodel.a", zVar2.w);
                c0122z.u("com.quizlet.quizletandroid.ui.group.addclassset.viewmodel.a", zVar2.x);
                c0122z.u("com.quizlet.features.infra.folder.create.coursefolder.viewmodel.e", zVar2.y);
                c0122z.u("com.quizlet.features.infra.folder.create.viewmodel.b", zVar2.z);
                c0122z.u("com.quizlet.features.settings.viewmodels.i", zVar2.A);
                c0122z.u("com.quizlet.quizletandroid.ui.group.addclassset.viewmodel.b", zVar2.B);
                c0122z.u("com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.h", zVar2.C);
                c0122z.u("com.quizlet.quizletandroid.ui.deeplinkinterstitial.i", zVar2.E);
                c0122z.u("com.quizlet.features.settings.viewmodels.k", zVar2.F);
                c0122z.u("com.quizlet.features.match.viewmodel.d", zVar2.G);
                c0122z.u("com.quizlet.diagrams.ui.i", zVar2.H);
                c0122z.u("com.quizlet.edgy.ui.viewmodel.e", zVar2.I);
                c0122z.u("com.quizlet.edgy.ui.viewmodel.w", zVar2.J);
                c0122z.u("com.quizlet.edgy.ui.viewmodel.M", zVar2.K);
                c0122z.u("com.quizlet.quizletandroid.ui.setcreation.viewmodels.e", zVar2.L);
                c0122z.u("com.quizlet.features.folders.edittags.viewmodel.c", zVar2.M);
                c0122z.u("com.quizlet.features.emailconfirmation.viewmodel.f", zVar2.N);
                c0122z.u("com.quizlet.features.notes.detail.viewmodels.c", zVar2.O);
                c0122z.u("com.quizlet.explanations.textbook.exercisedetail.viewmodel.c", zVar2.P);
                c0122z.u("com.quizlet.explanations.landingpage.viewmodel.a", zVar2.Q);
                c0122z.u("com.quizlet.explanations.feedback.viewmodel.a", zVar2.R);
                c0122z.u("com.quizlet.explanations.solution.viewmodel.b", zVar2.S);
                c0122z.u("com.quizlet.features.questiontypes.fitb.m", zVar2.T);
                c0122z.u("com.quizlet.features.flashcards.settings.j", zVar2.U);
                c0122z.u("com.quizlet.features.flashcards.S", zVar2.V);
                c0122z.u("com.quizlet.features.folders.viewmodel.N", zVar2.W);
                c0122z.u("com.quizlet.features.blocks.g", zVar2.X);
                c0122z.u("com.quizlet.quizletandroid.ui.globalnav.viewmodel.e", zVar2.Y);
                c0122z.u("com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L", zVar2.Z);
                c0122z.u("com.quizlet.features.home.viewmodel.c", zVar2.a0);
                c0122z.u("com.quizlet.login.intro.viewmodel.e", zVar2.c0);
                c0122z.u("com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.d", zVar2.d0);
                c0122z.u("com.quizlet.learn.viewmodel.c", zVar2.e0);
                c0122z.u("com.quizlet.learn.viewmodel.i", zVar2.f0);
                c0122z.u("com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.i", zVar2.g0);
                c0122z.u("com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel.g", zVar2.h0);
                c0122z.u("com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.i", zVar2.i0);
                c0122z.u("com.quizlet.learn.viewmodel.G", zVar2.k0);
                c0122z.u("com.quizlet.library.viewmodels.d", zVar2.l0);
                c0122z.u("com.quizlet.library.viewmodels.l", zVar2.m0);
                c0122z.u("com.quizlet.library.viewmodels.s", zVar2.n0);
                c0122z.u("com.quizlet.quizletandroid.ui.library.c0", zVar2.o0);
                c0122z.u("com.quizlet.quizletandroid.ui.setpage.addset.f", zVar2.p0);
                c0122z.u("com.quizlet.login.login.viewmodel.f", zVar2.q0);
                c0122z.u("com.quizlet.features.emailconfirmation.viewmodel.m", zVar2.r0);
                c0122z.u("com.quizlet.login.magiclink.viewmodel.g", zVar2.s0);
                c0122z.u("com.quizlet.login.magiclink.viewmodel.j", zVar2.t0);
                c0122z.u("com.quizlet.features.notes.detail.viewmodels.v", zVar2.u0);
                c0122z.u("com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.a", zVar2.v0);
                c0122z.u("com.quizlet.features.match.viewmodel.f", zVar2.w0);
                c0122z.u("com.quizlet.features.match.viewmodel.h", zVar2.x0);
                c0122z.u("com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.g", zVar2.y0);
                c0122z.u("com.quizlet.quizletandroid.ui.login.accountrecovery.loginduplicate.d", zVar2.z0);
                c0122z.u("com.quizlet.features.questiontypes.mcq.l", zVar2.A0);
                c0122z.u("com.quizlet.explanations.myexplanations.viewmodel.b", zVar2.B0);
                c0122z.u("com.quizlet.explanations.myexplanations.viewmodel.m", zVar2.C0);
                c0122z.u("com.quizlet.search.viewmodels.p", zVar2.E0);
                c0122z.u("com.quizlet.features.infra.folder.tag.viewmodel.d", zVar2.F0);
                c0122z.u("com.quizlet.login.recovery.forgotpassword.viewmodel.e", zVar2.G0);
                c0122z.u("com.quizlet.login.oldlogin.o", zVar2.H0);
                c0122z.u("com.quizlet.quizletandroid.ui.login.viewmodels.f", zVar2.I0);
                c0122z.u("com.quizlet.features.onboarding.ell.B", zVar2.J0);
                c0122z.u("com.quizlet.features.onboarding.flashcards.n", zVar2.K0);
                c0122z.u("com.quizlet.features.onboarding.navigation.p", zVar2.L0);
                c0122z.u("com.quizlet.features.onboarding.survey.q", zVar2.M0);
                c0122z.u("com.quizlet.login.parentemail.viewmodel.e", zVar2.N0);
                c0122z.u("com.quizlet.features.notes.upload.viewmodels.e", zVar2.O0);
                c0122z.u("com.quizlet.features.practicetest.detail.viewmodel.i", zVar2.P0);
                c0122z.u("com.quizlet.features.practicetest.results.viewmodel.h", zVar2.Q0);
                c0122z.u("com.quizlet.features.practicetest.takingtest.viewmodel.l", zVar2.R0);
                c0122z.u("com.quizlet.quizletandroid.ui.profile.o", zVar2.S0);
                c0122z.u("com.quizlet.quizletandroid.ui.profile.data.h", zVar2.T0);
                c0122z.u("com.quizlet.explanations.questiondetail.viewmodel.f", zVar2.U0);
                c0122z.u("com.quizlet.features.questiontypes.basequestion.k", zVar2.V0);
                c0122z.u("com.quizlet.features.questionnaire.navigation.m", zVar2.W0);
                c0122z.u("com.quizlet.quizletandroid.ui.live.QuizletLiveViewModel", zVar2.X0);
                c0122z.u("com.quizlet.features.settings.viewmodels.u", zVar2.Y0);
                c0122z.u("com.quizlet.report.viewmodels.c", zVar2.Z0);
                c0122z.u("com.quizlet.login.resetpassword.viewmodel.c", zVar2.a1);
                c0122z.u("com.quizlet.features.infra.folder.save.viewmodel.c", zVar2.b1);
                c0122z.u("com.quizlet.quizletandroid.ui.setcreation.viewmodels.h", zVar2.e1);
                c0122z.u("com.quizlet.features.notes.paywall.l", zVar2.f1);
                c0122z.u("com.quizlet.search.viewmodels.r", zVar2.g1);
                c0122z.u("com.quizlet.search.viewmodels.u", zVar2.h1);
                c0122z.u("com.quizlet.search.viewmodels.x", zVar2.i1);
                c0122z.u("com.quizlet.search.viewmodels.A", zVar2.j1);
                c0122z.u("com.quizlet.search.viewmodels.D", zVar2.k1);
                c0122z.u("com.quizlet.search.viewmodels.G", zVar2.l1);
                c0122z.u("com.quizlet.security.challenge.viewmodel.d", zVar2.m1);
                c0122z.u("com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.o", zVar2.n1);
                c0122z.u("com.quizlet.features.setpage.viewmodel.selectedtermsmode.b", zVar2.o1);
                c0122z.u("com.quizlet.features.questiontypes.selfassessment.h", zVar2.p1);
                c0122z.u("com.quizlet.quizletandroid.ui.onboarding.h", zVar2.q1);
                c0122z.u("com.quizlet.features.setpage.header.viewmodel.f", zVar2.r1);
                c0122z.u("com.quizlet.features.setpage.viewmodel.SetPageMobileWebViewModel", zVar2.s1);
                c0122z.u("com.quizlet.features.setpage.progress.presentation.viewmodel.a", zVar2.t1);
                c0122z.u("com.quizlet.features.setpage.viewmodel.P", zVar2.w1);
                c0122z.u("com.quizlet.quizletandroid.ui.preview.viewmodel.g", zVar2.x1);
                c0122z.u("com.quizlet.features.settings.viewmodels.I", zVar2.y1);
                c0122z.u("com.quizlet.login.signup.viewmodel.g", zVar2.z1);
                c0122z.u("com.quizlet.login.signupwall.viewmodel.a", zVar2.A1);
                c0122z.u("com.quizlet.features.match.viewmodel.i", zVar2.B1);
                c0122z.u("com.quizlet.quizletandroid.ui.group.addclassset.viewmodel.c", zVar2.C1);
                c0122z.u("com.quizlet.features.setpage.studypreview.g", zVar2.D1);
                c0122z.u("com.quizlet.quizletandroid.ui.subject.viewmodel.m", zVar2.F1);
                c0122z.u("com.quizlet.explanations.textbook.tableofcontents.viewmodel.b", zVar2.G1);
                c0122z.u("com.quizlet.features.setpage.termlist.viewmodel.j", zVar2.H1);
                c0122z.u("com.quizlet.features.setpage.terms.viewmodel.c", zVar2.I1);
                c0122z.u("com.quizlet.search.viewmodels.M", zVar2.J1);
                c0122z.u("com.quizlet.quizletandroid.ui.studymodes.testmode.start.A", zVar2.K1);
                c0122z.u("com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.t", zVar2.L1);
                c0122z.u("com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.G", zVar2.M1);
                c0122z.u("com.quizlet.explanations.textbook.viewmodel.c", zVar2.N1);
                c0122z.u("com.quizlet.features.questiontypes.truefalse.l", zVar2.O1);
                c0122z.u("com.quizlet.features.universaluploadflow.flashcards.viewmodel.e", zVar2.S1);
                c0122z.u("com.quizlet.features.universaluploadflow.pastetext.viewmodel.d", zVar2.T1);
                c0122z.u("com.quizlet.features.universaluploadflow.viewmodel.g", zVar2.U1);
                c0122z.u("com.quizlet.upgrade.ui.confirmation.c", zVar2.V1);
                c0122z.u("com.quizlet.upgrade.viewmodel.h", zVar2.W1);
                c0122z.u("com.quizlet.upgrade.viewmodel.k", zVar2.X1);
                c0122z.u("com.quizlet.upgrade.viewmodel.n", zVar2.Y1);
                c0122z.u("com.quizlet.features.notes.upload.viewmodels.k", zVar2.Z1);
                c0122z.u("com.quizlet.upgrade.upsell.viewmodel.c", zVar2.a2);
                c0122z.u("com.quizlet.features.userprofile.data.x", zVar2.b2);
                c0122z.u("com.quizlet.features.questiontypes.written.o", zVar2.c2);
                javax.inject.a aVar = (javax.inject.a) c0122z.h().get(modelClass.getName());
                Function1 function12 = (Function1) extras.a(dagger.hilt.android.internal.lifecycle.f.d);
                ((dagger.hilt.android.internal.lifecycle.e) K6.b(dagger.hilt.android.internal.lifecycle.e.class, zVar)).getClass();
                Object obj = C.g.get(modelClass);
                if (obj == null) {
                    if (function12 != null) {
                        throw new IllegalStateException(assistantMode.refactored.a.i(modelClass, new StringBuilder("Found creation callback but class "), " does not have an assisted factory specified in @HiltViewModel."));
                    }
                    if (aVar == null) {
                        throw new IllegalStateException(assistantMode.refactored.a.i(modelClass, new StringBuilder("Expected the @HiltViewModel-annotated class "), " to be available in the multi-binding of @HiltViewModelMap but none was found."));
                    }
                    w0Var2 = (w0) aVar.get();
                } else {
                    if (aVar != null) {
                        throw new AssertionError(assistantMode.refactored.a.i(modelClass, new StringBuilder("Found the @HiltViewModel-annotated class "), " in both the multi-bindings of @HiltViewModelMap and @HiltViewModelAssistedMap."));
                    }
                    if (function12 == null) {
                        throw new IllegalStateException(assistantMode.refactored.a.i(modelClass, new StringBuilder("Found @HiltViewModel-annotated class "), " using @AssistedInject but no creation callback was provided in CreationExtras."));
                    }
                    w0Var2 = (w0) function12.invoke(obj);
                }
                dagger.hilt.android.internal.lifecycle.c closeable = new dagger.hilt.android.internal.lifecycle.c(hVar);
                w0Var2.getClass();
                Intrinsics.checkNotNullParameter(closeable, "closeable");
                androidx.lifecycle.viewmodel.internal.d dVar = w0Var2.a;
                if (dVar != null) {
                    Intrinsics.checkNotNullParameter(closeable, "closeable");
                    if (dVar.d) {
                        androidx.lifecycle.viewmodel.internal.d.a(closeable);
                    } else {
                        synchronized (dVar.a) {
                            dVar.c.add(closeable);
                            Unit unit = Unit.a;
                        }
                    }
                }
                return w0Var2;
            default:
                com.quizlet.login.authentication.login.a aVar2 = new com.quizlet.login.authentication.login.a(19);
                aVar2.b = extras;
                return new dagger.hilt.android.internal.managers.d(new C4624g(((u) ((dagger.hilt.android.internal.managers.c) L6.b((s) this.b, dagger.hilt.android.internal.managers.c.class))).n, new com.google.mlkit.common.sdkinternal.model.a(27)), aVar2);
        }
    }

    public d(f[] initializers) {
        this.a = 0;
        Intrinsics.checkNotNullParameter(initializers, "initializers");
        this.b = initializers;
    }
}

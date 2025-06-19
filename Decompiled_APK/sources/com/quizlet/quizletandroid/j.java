package com.quizlet.quizletandroid;

import android.content.Context;
import androidx.fragment.app.Fragment;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import com.quizlet.edgy.ui.fragment.InterfaceC4191e;
import com.quizlet.edgy.ui.fragment.M;
import com.quizlet.quizletandroid.ui.library.InterfaceC4670o;
import com.quizlet.quizletandroid.ui.startpage.nav2.InterfaceC4729t;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class j implements com.features.flashcards.creatormarketing.g, com.quizlet.ads.ui.fragments.d, com.quizlet.ads.ui.fragments.f, com.quizlet.ads.ui.fragments.i, com.quizlet.ads.ui.fragments.k, InterfaceC4191e, com.quizlet.edgy.ui.fragment.s, com.quizlet.edgy.ui.fragment.H, M, com.quizlet.explanations.feedback.ui.fragments.d, com.quizlet.explanations.feedback.ui.fragments.e, com.quizlet.explanations.feedback.ui.fragments.i, com.quizlet.explanations.feedback.ui.fragments.k, com.quizlet.explanations.myexplanations.ui.fragments.b, com.quizlet.explanations.questiondetail.ui.h, com.quizlet.explanations.solution.fragments.d, com.quizlet.explanations.textbook.chaptermenu.ui.c, com.quizlet.explanations.textbook.exercisedetail.ui.e, com.quizlet.explanations.textbook.tableofcontents.ui.b, com.quizlet.explanations.textbook.ui.g, com.quizlet.features.achievements.ui.d, com.quizlet.features.infra.folder.create.d, com.quizlet.features.onboarding.ell.e, com.quizlet.features.questiontypes.coordinator.b, com.quizlet.features.questiontypes.fitb.f, com.quizlet.features.questiontypes.mcq.d, com.quizlet.features.questiontypes.selfassessment.b, com.quizlet.features.questiontypes.truefalse.g, com.quizlet.features.questiontypes.written.h, com.quizlet.features.setpage.header.ui.f, com.quizlet.features.setpage.progress.presentation.ui.b, com.quizlet.features.setpage.studypreview.c, com.quizlet.features.setpage.termlist.d, com.quizlet.features.setpage.terms.ui.c, com.quizlet.features.userprofile.ui.c, com.quizlet.login.magiclink.ui.k, com.quizlet.login.magiclink.ui.q, com.quizlet.login.recovery.forgotpassword.ui.g, com.quizlet.quizletandroid.ui.activitycenter.fragments.b, com.quizlet.quizletandroid.ui.activitycenter.fragments.e, com.quizlet.quizletandroid.ui.activitycenter.fragments.i, com.quizlet.quizletandroid.ui.diagramming.i, com.quizlet.quizletandroid.ui.group.h, com.quizlet.quizletandroid.ui.group.addclassset.e, com.quizlet.quizletandroid.ui.group.addclassset.f, com.quizlet.quizletandroid.ui.group.addclassset.g, com.quizlet.quizletandroid.ui.group.classcontent.b, com.quizlet.quizletandroid.ui.group.classuser.b, InterfaceC4670o, com.quizlet.quizletandroid.ui.login.m, com.quizlet.quizletandroid.ui.login.o, com.quizlet.quizletandroid.ui.login.w, com.quizlet.quizletandroid.ui.login.y, com.quizlet.quizletandroid.ui.login.D, com.quizlet.quizletandroid.ui.login.accountrecovery.a, com.quizlet.quizletandroid.ui.login.accountrecovery.loginduplicate.c, com.quizlet.quizletandroid.ui.login.accountrecovery.signupduplicate.d, com.quizlet.quizletandroid.ui.profile.h, com.quizlet.quizletandroid.ui.profile.n, com.quizlet.quizletandroid.ui.qrcodes.g, com.quizlet.quizletandroid.ui.setcreation.fragments.j, com.quizlet.quizletandroid.ui.setcreation.fragments.p, com.quizlet.quizletandroid.ui.setpage.h, com.quizlet.quizletandroid.ui.setpage.addset.e, com.quizlet.quizletandroid.ui.setpage.shareset.d, com.quizlet.quizletandroid.ui.setpage.terms.h, InterfaceC4729t, com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.e, com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.j, com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.o, com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.r, com.quizlet.quizletandroid.ui.studymodes.match.fragment.e, com.quizlet.quizletandroid.ui.studymodes.match.fragment.i, com.quizlet.quizletandroid.ui.studymodes.match.fragment.l, com.quizlet.quizletandroid.ui.studymodes.match.fragment.p, com.quizlet.quizletandroid.ui.studymodes.match.fragment.u, com.quizlet.quizletandroid.ui.studymodes.match.fragment.challenge.d, com.quizlet.quizletandroid.ui.studymodes.match.settings.c, com.quizlet.quizletandroid.ui.studymodes.testmode.fragments.c, com.quizlet.quizletandroid.ui.studymodes.testmode.start.o, com.quizlet.quizletandroid.ui.studymodes.write.o, com.quizlet.quizletandroid.ui.usersettings.fragments.d, com.quizlet.quizletandroid.ui.usersettings.fragments.e, com.quizlet.search.g, com.quizlet.search.l, com.quizlet.upgrade.ui.confirmation.b, com.quizlet.upgrade.ui.fragment.b, com.quizlet.upgrade.ui.fragment.c, com.quizlet.upgrade.ui.fragment.i, com.quizlet.upgrade.ui.fragment.n, com.quizlet.upgrade.upsell.ui.h, dagger.hilt.android.internal.lifecycle.b, dagger.hilt.internal.a {
    public final Fragment a;
    public final u b;
    public final C4624g c;
    public final C4622e d;
    public final dagger.internal.c e;
    public final dagger.internal.c f;

    public j(u uVar, C4624g c4624g, C4622e c4622e, Fragment fragment) {
        this.b = uVar;
        this.c = c4624g;
        this.d = c4622e;
        this.a = fragment;
        this.e = dagger.internal.d.a(new C4626i(uVar, 0));
        this.f = dagger.internal.d.a(new C4626i(uVar, 1));
    }

    public final com.quizlet.ads.ui.fragments.a a() {
        Fragment fragment = this.a;
        Intrinsics.checkNotNullParameter(fragment, "fragment");
        Context contextRequireContext = fragment.requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        S6.c(contextRequireContext);
        return new com.quizlet.ads.ui.fragments.a(contextRequireContext);
    }
}

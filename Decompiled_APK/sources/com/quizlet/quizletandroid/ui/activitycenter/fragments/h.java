package com.quizlet.quizletandroid.ui.activitycenter.fragments;

import androidx.lifecycle.C0;
import androidx.lifecycle.InterfaceC1261w;
import androidx.lifecycle.y0;
import com.comscore.streaming.EventType;
import com.quizlet.quizletandroid.ui.group.classcontent.ClassContentListFragment;
import com.quizlet.quizletandroid.ui.login.BaseSignupFragment;
import com.quizlet.quizletandroid.ui.login.ParentEmailFragment;
import com.quizlet.quizletandroid.ui.login.SignUpWallModalFragment;
import com.quizlet.quizletandroid.ui.login.accountrecovery.loginduplicate.MultipleAccountsExistPromptFragment;
import com.quizlet.quizletandroid.ui.login.accountrecovery.signupduplicate.AccountAlreadyExistsPromptFragment;
import com.quizlet.quizletandroid.ui.profile.ProfileUserClassListFragment;
import com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment;
import com.quizlet.quizletandroid.ui.setcreation.fragments.ScanDocumentFragment;
import com.quizlet.quizletandroid.ui.setpage.addset.LoggedInUserClassSelectionListFragment;
import com.quizlet.quizletandroid.ui.setpage.terms.TermListFragment;
import com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.LearnCheckpointFragment;
import com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.LearnEndingFragment;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.DiagramMatchGameFragment;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.MatchEndGameFragment;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.MatchGameFragment;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.MatchStartGameFragment;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.StandardMatchGameFragment;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.j;
import com.quizlet.quizletandroid.ui.studymodes.testmode.start.TestModeStartFragment;
import com.quizlet.quizletandroid.ui.usersettings.fragments.ChangeProfileImageFragment;
import com.quizlet.search.NewSearchFragment;
import com.quizlet.search.TermSearchFragment;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.r;
import kotlin.k;

/* loaded from: classes3.dex */
public final class h extends r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ h(Object obj, k kVar, int i) {
        super(0);
        this.a = i;
        this.c = obj;
        this.b = kVar;
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v103, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v113, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v127, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v135, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v145, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v15, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v155, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v169, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v177, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v191, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v199, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v213, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v221, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v23, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v235, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v243, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v257, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v265, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v275, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v285, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v295, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v305, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v33, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v43, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v53, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v63, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v73, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v83, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v93, types: [java.lang.Object, kotlin.k] */
    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
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
        y0 defaultViewModelProviderFactory12;
        y0 defaultViewModelProviderFactory13;
        y0 defaultViewModelProviderFactory14;
        y0 defaultViewModelProviderFactory15;
        y0 defaultViewModelProviderFactory16;
        y0 defaultViewModelProviderFactory17;
        y0 defaultViewModelProviderFactory18;
        y0 defaultViewModelProviderFactory19;
        y0 defaultViewModelProviderFactory20;
        y0 defaultViewModelProviderFactory21;
        y0 defaultViewModelProviderFactory22;
        y0 defaultViewModelProviderFactory23;
        switch (this.a) {
            case 0:
                C0 c0 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w = c0 instanceof InterfaceC1261w ? (InterfaceC1261w) c0 : null;
                return (interfaceC1261w == null || (defaultViewModelProviderFactory = interfaceC1261w.getDefaultViewModelProviderFactory()) == null) ? ((ActivityCenterModalFragment) this.c).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory;
            case 1:
                androidx.lifecycle.viewmodel.c cVar = (androidx.lifecycle.viewmodel.c) ((com.quizlet.login.magiclink.ui.e) this.c).invoke();
                if (cVar != null) {
                    return cVar;
                }
                C0 c02 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w2 = c02 instanceof InterfaceC1261w ? (InterfaceC1261w) c02 : null;
                return interfaceC1261w2 != null ? interfaceC1261w2.getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b;
            case 2:
                C0 c03 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w3 = c03 instanceof InterfaceC1261w ? (InterfaceC1261w) c03 : null;
                return (interfaceC1261w3 == null || (defaultViewModelProviderFactory2 = interfaceC1261w3.getDefaultViewModelProviderFactory()) == null) ? ((ClassContentListFragment) this.c).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory2;
            case 3:
                C0 c04 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w4 = c04 instanceof InterfaceC1261w ? (InterfaceC1261w) c04 : null;
                return (interfaceC1261w4 == null || (defaultViewModelProviderFactory3 = interfaceC1261w4.getDefaultViewModelProviderFactory()) == null) ? ((BaseSignupFragment) this.c).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory3;
            case 4:
                C0 c05 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w5 = c05 instanceof InterfaceC1261w ? (InterfaceC1261w) c05 : null;
                return (interfaceC1261w5 == null || (defaultViewModelProviderFactory4 = interfaceC1261w5.getDefaultViewModelProviderFactory()) == null) ? ((ParentEmailFragment) this.c).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory4;
            case 5:
                C0 c06 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w6 = c06 instanceof InterfaceC1261w ? (InterfaceC1261w) c06 : null;
                return (interfaceC1261w6 == null || (defaultViewModelProviderFactory5 = interfaceC1261w6.getDefaultViewModelProviderFactory()) == null) ? ((SignUpWallModalFragment) this.c).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory5;
            case 6:
                C0 c07 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w7 = c07 instanceof InterfaceC1261w ? (InterfaceC1261w) c07 : null;
                return (interfaceC1261w7 == null || (defaultViewModelProviderFactory6 = interfaceC1261w7.getDefaultViewModelProviderFactory()) == null) ? ((MultipleAccountsExistPromptFragment) this.c).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory6;
            case 7:
                C0 c08 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w8 = c08 instanceof InterfaceC1261w ? (InterfaceC1261w) c08 : null;
                return (interfaceC1261w8 == null || (defaultViewModelProviderFactory7 = interfaceC1261w8.getDefaultViewModelProviderFactory()) == null) ? ((AccountAlreadyExistsPromptFragment) this.c).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory7;
            case 8:
                C0 c09 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w9 = c09 instanceof InterfaceC1261w ? (InterfaceC1261w) c09 : null;
                return (interfaceC1261w9 == null || (defaultViewModelProviderFactory8 = interfaceC1261w9.getDefaultViewModelProviderFactory()) == null) ? ((ProfileUserClassListFragment) this.c).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory8;
            case 9:
                C0 c010 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w10 = c010 instanceof InterfaceC1261w ? (InterfaceC1261w) c010 : null;
                return (interfaceC1261w10 == null || (defaultViewModelProviderFactory9 = interfaceC1261w10.getDefaultViewModelProviderFactory()) == null) ? ((EditSetFragment) this.c).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory9;
            case 10:
                C0 c011 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w11 = c011 instanceof InterfaceC1261w ? (InterfaceC1261w) c011 : null;
                return (interfaceC1261w11 == null || (defaultViewModelProviderFactory10 = interfaceC1261w11.getDefaultViewModelProviderFactory()) == null) ? ((ScanDocumentFragment) this.c).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory10;
            case 11:
                C0 c012 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w12 = c012 instanceof InterfaceC1261w ? (InterfaceC1261w) c012 : null;
                return (interfaceC1261w12 == null || (defaultViewModelProviderFactory11 = interfaceC1261w12.getDefaultViewModelProviderFactory()) == null) ? ((LoggedInUserClassSelectionListFragment) this.c).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory11;
            case 12:
                androidx.lifecycle.viewmodel.c cVar2 = (androidx.lifecycle.viewmodel.c) ((com.quizlet.quizletandroid.ui.setpage.terms.a) this.c).invoke();
                if (cVar2 != null) {
                    return cVar2;
                }
                C0 c013 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w13 = c013 instanceof InterfaceC1261w ? (InterfaceC1261w) c013 : null;
                return interfaceC1261w13 != null ? interfaceC1261w13.getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b;
            case 13:
                C0 c014 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w14 = c014 instanceof InterfaceC1261w ? (InterfaceC1261w) c014 : null;
                return (interfaceC1261w14 == null || (defaultViewModelProviderFactory12 = interfaceC1261w14.getDefaultViewModelProviderFactory()) == null) ? ((TermListFragment) this.c).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory12;
            case 14:
                C0 c015 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w15 = c015 instanceof InterfaceC1261w ? (InterfaceC1261w) c015 : null;
                return (interfaceC1261w15 == null || (defaultViewModelProviderFactory13 = interfaceC1261w15.getDefaultViewModelProviderFactory()) == null) ? ((LearnCheckpointFragment) this.c).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory13;
            case 15:
                C0 c016 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w16 = c016 instanceof InterfaceC1261w ? (InterfaceC1261w) c016 : null;
                return (interfaceC1261w16 == null || (defaultViewModelProviderFactory14 = interfaceC1261w16.getDefaultViewModelProviderFactory()) == null) ? ((LearnEndingFragment) this.c).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory14;
            case 16:
                androidx.lifecycle.viewmodel.c cVar3 = (androidx.lifecycle.viewmodel.c) ((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a) this.c).invoke();
                if (cVar3 != null) {
                    return cVar3;
                }
                C0 c017 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w17 = c017 instanceof InterfaceC1261w ? (InterfaceC1261w) c017 : null;
                return interfaceC1261w17 != null ? interfaceC1261w17.getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b;
            case 17:
                C0 c018 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w18 = c018 instanceof InterfaceC1261w ? (InterfaceC1261w) c018 : null;
                return (interfaceC1261w18 == null || (defaultViewModelProviderFactory15 = interfaceC1261w18.getDefaultViewModelProviderFactory()) == null) ? ((DiagramMatchGameFragment) this.c).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory15;
            case 18:
                androidx.lifecycle.viewmodel.c cVar4 = (androidx.lifecycle.viewmodel.c) ((com.quizlet.quizletandroid.ui.studymodes.match.fragment.g) this.c).invoke();
                if (cVar4 != null) {
                    return cVar4;
                }
                C0 c019 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w19 = c019 instanceof InterfaceC1261w ? (InterfaceC1261w) c019 : null;
                return interfaceC1261w19 != null ? interfaceC1261w19.getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b;
            case 19:
                C0 c020 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w20 = c020 instanceof InterfaceC1261w ? (InterfaceC1261w) c020 : null;
                return (interfaceC1261w20 == null || (defaultViewModelProviderFactory16 = interfaceC1261w20.getDefaultViewModelProviderFactory()) == null) ? ((MatchEndGameFragment) this.c).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory16;
            case 20:
                androidx.lifecycle.viewmodel.c cVar5 = (androidx.lifecycle.viewmodel.c) ((j) this.c).invoke();
                if (cVar5 != null) {
                    return cVar5;
                }
                C0 c021 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w21 = c021 instanceof InterfaceC1261w ? (InterfaceC1261w) c021 : null;
                return interfaceC1261w21 != null ? interfaceC1261w21.getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b;
            case 21:
                C0 c022 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w22 = c022 instanceof InterfaceC1261w ? (InterfaceC1261w) c022 : null;
                return (interfaceC1261w22 == null || (defaultViewModelProviderFactory17 = interfaceC1261w22.getDefaultViewModelProviderFactory()) == null) ? ((MatchGameFragment) this.c).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory17;
            case EventType.WINDOW_STATE /* 22 */:
                androidx.lifecycle.viewmodel.c cVar6 = (androidx.lifecycle.viewmodel.c) ((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a) this.c).invoke();
                if (cVar6 != null) {
                    return cVar6;
                }
                C0 c023 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w23 = c023 instanceof InterfaceC1261w ? (InterfaceC1261w) c023 : null;
                return interfaceC1261w23 != null ? interfaceC1261w23.getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b;
            case EventType.AUDIO /* 23 */:
                C0 c024 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w24 = c024 instanceof InterfaceC1261w ? (InterfaceC1261w) c024 : null;
                return (interfaceC1261w24 == null || (defaultViewModelProviderFactory18 = interfaceC1261w24.getDefaultViewModelProviderFactory()) == null) ? ((MatchStartGameFragment) this.c).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory18;
            case EventType.VIDEO /* 24 */:
                androidx.lifecycle.viewmodel.c cVar7 = (androidx.lifecycle.viewmodel.c) ((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a) this.c).invoke();
                if (cVar7 != null) {
                    return cVar7;
                }
                C0 c025 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w25 = c025 instanceof InterfaceC1261w ? (InterfaceC1261w) c025 : null;
                return interfaceC1261w25 != null ? interfaceC1261w25.getDefaultViewModelCreationExtras() : androidx.lifecycle.viewmodel.a.b;
            case EventType.SUBS /* 25 */:
                C0 c026 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w26 = c026 instanceof InterfaceC1261w ? (InterfaceC1261w) c026 : null;
                return (interfaceC1261w26 == null || (defaultViewModelProviderFactory19 = interfaceC1261w26.getDefaultViewModelProviderFactory()) == null) ? ((StandardMatchGameFragment) this.c).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory19;
            case EventType.CDN /* 26 */:
                C0 c027 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w27 = c027 instanceof InterfaceC1261w ? (InterfaceC1261w) c027 : null;
                return (interfaceC1261w27 == null || (defaultViewModelProviderFactory20 = interfaceC1261w27.getDefaultViewModelProviderFactory()) == null) ? ((TestModeStartFragment) this.c).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory20;
            case 27:
                C0 c028 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w28 = c028 instanceof InterfaceC1261w ? (InterfaceC1261w) c028 : null;
                return (interfaceC1261w28 == null || (defaultViewModelProviderFactory21 = interfaceC1261w28.getDefaultViewModelProviderFactory()) == null) ? ((ChangeProfileImageFragment) this.c).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory21;
            case 28:
                C0 c029 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w29 = c029 instanceof InterfaceC1261w ? (InterfaceC1261w) c029 : null;
                return (interfaceC1261w29 == null || (defaultViewModelProviderFactory22 = interfaceC1261w29.getDefaultViewModelProviderFactory()) == null) ? ((NewSearchFragment) this.c).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory22;
            default:
                C0 c030 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w30 = c030 instanceof InterfaceC1261w ? (InterfaceC1261w) c030 : null;
                return (interfaceC1261w30 == null || (defaultViewModelProviderFactory23 = interfaceC1261w30.getDefaultViewModelProviderFactory()) == null) ? ((TermSearchFragment) this.c).getDefaultViewModelProviderFactory() : defaultViewModelProviderFactory23;
        }
    }
}

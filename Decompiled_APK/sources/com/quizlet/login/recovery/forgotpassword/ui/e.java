package com.quizlet.login.recovery.forgotpassword.ui;

import androidx.lifecycle.C0;
import com.comscore.streaming.EventType;
import com.quizlet.quizletandroid.ui.activitycenter.fragments.ActivityCenterFragment;
import com.quizlet.quizletandroid.ui.activitycenter.fragments.ActivityCenterModalFragment;
import com.quizlet.quizletandroid.ui.group.classcontent.ClassContentListFragment;
import com.quizlet.quizletandroid.ui.library.C4669n;
import com.quizlet.quizletandroid.ui.login.SignUpWallModalFragment;
import com.quizlet.quizletandroid.ui.login.v;
import com.quizlet.quizletandroid.ui.profile.m;
import com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment;
import com.quizlet.quizletandroid.ui.setcreation.fragments.ScanDocumentFragment;
import com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.h;
import com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.n;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.DiagramMatchGameFragment;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.k;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.o;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class e extends r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ e(Object obj, int i) {
        super(0);
        this.a = i;
        this.b = obj;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return (C0) ((assistantMode.experiments.a) this.b).invoke();
            case 1:
                return Long.valueOf(((com.quizlet.progress.types.c) this.b).a);
            case 2:
                return (ActivityCenterFragment) this.b;
            case 3:
                return (C0) ((e) this.b).invoke();
            case 4:
                return (ActivityCenterModalFragment) this.b;
            case 5:
                return (C0) ((e) this.b).invoke();
            case 6:
                return (ClassContentListFragment) this.b;
            case 7:
                return (C0) ((e) this.b).invoke();
            case 8:
                return (C0) ((C4669n) this.b).invoke();
            case 9:
                return (C0) ((C4669n) this.b).invoke();
            case 10:
                return (C0) ((com.quizlet.quizletandroid.ui.login.e) this.b).invoke();
            case 11:
                return (C0) ((v) this.b).invoke();
            case 12:
                return (SignUpWallModalFragment) this.b;
            case 13:
                return (C0) ((e) this.b).invoke();
            case 14:
                return (C0) ((com.quizlet.quizletandroid.ui.login.accountrecovery.loginduplicate.b) this.b).invoke();
            case 15:
                return (C0) ((com.quizlet.quizletandroid.ui.login.accountrecovery.signupduplicate.c) this.b).invoke();
            case 16:
                return (C0) ((m) this.b).invoke();
            case 17:
                return (EditSetFragment) this.b;
            case 18:
                return (C0) ((e) this.b).invoke();
            case 19:
                return (ScanDocumentFragment) this.b;
            case 20:
                return (C0) ((e) this.b).invoke();
            case 21:
                return (C0) ((com.quizlet.quizletandroid.ui.setpage.addset.d) this.b).invoke();
            case EventType.WINDOW_STATE /* 22 */:
                return (C0) ((com.quizlet.quizletandroid.ui.setpage.terms.g) this.b).invoke();
            case EventType.AUDIO /* 23 */:
                return (C0) ((h) this.b).invoke();
            case EventType.VIDEO /* 24 */:
                return (C0) ((n) this.b).invoke();
            case EventType.SUBS /* 25 */:
                return (DiagramMatchGameFragment) this.b;
            case EventType.CDN /* 26 */:
                return (C0) ((e) this.b).invoke();
            case 27:
                return (C0) ((com.quizlet.quizletandroid.ui.studymodes.match.fragment.h) this.b).invoke();
            case 28:
                return (C0) ((k) this.b).invoke();
            default:
                return (C0) ((o) this.b).invoke();
        }
    }
}

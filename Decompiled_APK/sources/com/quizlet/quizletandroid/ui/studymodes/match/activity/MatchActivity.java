package com.quizlet.quizletandroid.ui.studymodes.match.activity;

import android.content.Intent;
import android.os.Bundle;
import android.os.Parcelable;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.activity.v;
import androidx.appcompat.widget.Toolbar;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.core.view.L;
import androidx.core.view.V;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.lifecycle.Y;
import androidx.lifecycle.d0;
import androidx.work.impl.A;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.ads.ui.activity.d;
import com.quizlet.baseui.base.BaseFragment;
import com.quizlet.data.repository.folderwithcreatorinclass.e;
import com.quizlet.data.repository.metering.j;
import com.quizlet.features.infra.legacyadapter.databinding.f;
import com.quizlet.features.match.data.AbstractC4368y;
import com.quizlet.features.match.data.C4348d;
import com.quizlet.features.match.settings.MatchSettingsData;
import com.quizlet.partskit.widgets.QProgressBar;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4604h;
import com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.g;
import com.quizlet.uicommon.ui.common.views.TimerTextView;
import io.reactivex.rxjava3.subjects.r;
import java.util.WeakHashMap;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes3.dex */
public final class MatchActivity extends d {
    public static final String s;
    public static final int t;
    public MenuItem q;
    public final e r;

    static {
        Intrinsics.checkNotNullExpressionValue("MatchActivity", "getSimpleName(...)");
        s = "MatchActivity";
        t = R.menu.match_menu;
    }

    public MatchActivity() {
        super(10);
        this.r = new e(K.a(g.class), new b(this, 1), new b(this, 0), new b(this, 2));
    }

    @Override // com.quizlet.baseui.base.b
    public final Integer B() {
        return Integer.valueOf(t);
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return s;
    }

    @Override // com.quizlet.baseui.base.f
    public final androidx.viewbinding.a N() {
        View viewInflate = getLayoutInflater().inflate(R.layout.activity_match_v2, (ViewGroup) null, false);
        int i = R.id.appBar;
        View viewC = AbstractC3375o2.c(R.id.appBar, viewInflate);
        if (viewC != null) {
            com.onetrust.otpublishers.headless.databinding.b bVarA = com.onetrust.otpublishers.headless.databinding.b.a(viewC);
            i = R.id.frameLayout;
            FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.frameLayout, viewInflate);
            if (frameLayout != null) {
                i = R.id.loadingIndicator;
                QProgressBar qProgressBar = (QProgressBar) AbstractC3375o2.c(R.id.loadingIndicator, viewInflate);
                if (qProgressBar != null) {
                    i = R.id.matchBar;
                    View viewC2 = AbstractC3375o2.c(R.id.matchBar, viewInflate);
                    if (viewC2 != null) {
                        int i2 = R.id.match_bar_timer;
                        TimerTextView timerTextView = (TimerTextView) AbstractC3375o2.c(R.id.match_bar_timer, viewC2);
                        if (timerTextView != null) {
                            i2 = R.id.match_bar_title;
                            QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.match_bar_title, viewC2);
                            if (qTextView != null) {
                                FrameLayout frameLayout2 = (FrameLayout) viewC2;
                                f fVar = new f(frameLayout2, timerTextView, qTextView, frameLayout2, 4);
                                i = R.id.matchGameFragment;
                                FrameLayout frameLayout3 = (FrameLayout) AbstractC3375o2.c(R.id.matchGameFragment, viewInflate);
                                if (frameLayout3 != null) {
                                    C4604h c4604h = new C4604h((ConstraintLayout) viewInflate, bVarA, frameLayout, qProgressBar, fVar, frameLayout3);
                                    Intrinsics.checkNotNullExpressionValue(c4604h, "inflate(...)");
                                    return c4604h;
                                }
                            }
                        }
                        throw new NullPointerException("Missing required view with ID: ".concat(viewC2.getResources().getResourceName(i2)));
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final TimerTextView b0() {
        TimerTextView matchBarTimer = (TimerTextView) ((C4604h) K()).e.c;
        Intrinsics.checkNotNullExpressionValue(matchBarTimer, "matchBarTimer");
        return matchBarTimer;
    }

    public final FrameLayout c0() {
        FrameLayout matchGameFragment = ((C4604h) K()).f;
        Intrinsics.checkNotNullExpressionValue(matchGameFragment, "matchGameFragment");
        return matchGameFragment;
    }

    public final g d0() {
        return (g) this.r.getValue();
    }

    public final void e0(BaseFragment baseFragment, String str) {
        if (getSupportFragmentManager().E(str) != null) {
            return;
        }
        AbstractC1136h0 supportFragmentManager = getSupportFragmentManager();
        supportFragmentManager.getClass();
        C1121a c1121a = new C1121a(supportFragmentManager);
        c1121a.l(R.id.matchGameFragment, baseFragment, str);
        c1121a.g();
    }

    public final void f0(boolean z) {
        if (z) {
            QProgressBar loadingIndicator = ((C4604h) K()).d;
            Intrinsics.checkNotNullExpressionValue(loadingIndicator, "loadingIndicator");
            loadingIndicator.setVisibility(0);
            c0().setVisibility(8);
            return;
        }
        QProgressBar loadingIndicator2 = ((C4604h) K()).d;
        Intrinsics.checkNotNullExpressionValue(loadingIndicator2, "loadingIndicator");
        loadingIndicator2.setVisibility(8);
        c0().setVisibility(0);
    }

    @Override // com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, android.app.Activity
    public final void onActivityResult(int i, int i2, Intent intent) {
        super.onActivityResult(i, i2, intent);
        if (i != 1 || intent == null) {
            return;
        }
        Parcelable parcelableExtra = intent.getParcelableExtra("settings");
        if (parcelableExtra == null) {
            throw new IllegalArgumentException("Received null MatchSettingsData from MatchSettings");
        }
        MatchSettingsData settings = (MatchSettingsData) parcelableExtra;
        boolean booleanExtra = intent.getBooleanExtra("shouldRestart", false);
        g gVarD0 = d0();
        gVarD0.getClass();
        Intrinsics.checkNotNullParameter(settings, "settingsToBeSaved");
        j jVar = gVarD0.i;
        jVar.getClass();
        Intrinsics.checkNotNullParameter(settings, "settings");
        r rVar = (r) jVar.d;
        rVar.getClass();
        io.reactivex.rxjava3.internal.operators.completable.a aVar = new io.reactivex.rxjava3.internal.operators.completable.a(0, new io.reactivex.rxjava3.internal.operators.completable.c(rVar, 6), new io.reactivex.rxjava3.internal.operators.completable.c(new A(8, jVar, settings), 4));
        Intrinsics.checkNotNullExpressionValue(aVar, "andThen(...)");
        io.reactivex.rxjava3.internal.observers.e eVarF = aVar.f(new com.quizlet.quizletandroid.ui.login.authmanagers.a(booleanExtra, gVarD0, settings, 1), io.reactivex.rxjava3.internal.functions.d.e);
        Intrinsics.checkNotNullExpressionValue(eVarF, "subscribe(...)");
        Intrinsics.checkNotNullParameter(eVarF, "<this>");
        gVarD0.A(eVarF);
    }

    @Override // androidx.activity.s, android.app.Activity
    public final void onBackPressed() {
        g gVarD0 = d0();
        gVarD0.u.j(Boolean.valueOf(gVarD0.m.d() instanceof C4348d));
        gVarD0.D();
    }

    @Override // com.quizlet.ads.ui.activity.d, com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        final int i = 1;
        super.onCreate(bundle);
        final int i2 = 3;
        v.b(this, null, 3);
        C4604h c4604h = (C4604h) K();
        com.quizlet.infra.legacysyncengine.tasks.parse.b bVar = new com.quizlet.infra.legacysyncengine.tasks.parse.b(this, 21);
        WeakHashMap weakHashMap = V.a;
        L.m(c4604h.f, bVar);
        final int i3 = 2;
        d0().n.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(22, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.match.activity.a
            public final /* synthetic */ MatchActivity b;

            {
                this.b = this;
            }

            /* JADX WARN: Removed duplicated region for block: B:26:0x00b0  */
            @Override // kotlin.jvm.functions.Function1
            /*
                Code decompiled incorrectly, please refer to instructions dump.
                To view partially-correct add '--show-bad-code' argument
            */
            public final java.lang.Object invoke(java.lang.Object r25) throws java.lang.Throwable {
                /*
                    Method dump skipped, instructions count: 1738
                    To view this dump add '--comments-level debug' option
                */
                throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.match.activity.a.invoke(java.lang.Object):java.lang.Object");
            }
        }));
        final int i4 = 4;
        d0().o.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(22, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.match.activity.a
            public final /* synthetic */ MatchActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object v) throws Throwable {
                /*
                    Method dump skipped, instructions count: 1738
                    To view this dump add '--comments-level debug' option
                */
                throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.match.activity.a.invoke(java.lang.Object):java.lang.Object");
            }
        }));
        final int i5 = 5;
        d0().q.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(22, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.match.activity.a
            public final /* synthetic */ MatchActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object v) throws Throwable {
                /*
                    Method dump skipped, instructions count: 1738
                    To view this dump add '--comments-level debug' option
                */
                throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.match.activity.a.invoke(java.lang.Object):java.lang.Object");
            }
        }));
        final int i6 = 6;
        d0().p.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(22, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.match.activity.a
            public final /* synthetic */ MatchActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object v) throws Throwable {
                /*
                    Method dump skipped, instructions count: 1738
                    To view this dump add '--comments-level debug' option
                */
                throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.match.activity.a.invoke(java.lang.Object):java.lang.Object");
            }
        }));
        final int i7 = 7;
        d0().m.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(22, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.match.activity.a
            public final /* synthetic */ MatchActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object v) throws Throwable {
                /*
                    Method dump skipped, instructions count: 1738
                    To view this dump add '--comments-level debug' option
                */
                throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.match.activity.a.invoke(java.lang.Object):java.lang.Object");
            }
        }));
        final int i8 = 8;
        d0().l.m(this, new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a(this, 1), new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.match.activity.a
            public final /* synthetic */ MatchActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object v) throws Throwable {
                /*
                    Method dump skipped, instructions count: 1738
                    To view this dump add '--comments-level debug' option
                */
                throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.match.activity.a.invoke(java.lang.Object):java.lang.Object");
            }
        });
        final int i9 = 9;
        d0().r.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(22, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.match.activity.a
            public final /* synthetic */ MatchActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object v) throws Throwable {
                /*
                    Method dump skipped, instructions count: 1738
                    To view this dump add '--comments-level debug' option
                */
                throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.match.activity.a.invoke(java.lang.Object):java.lang.Object");
            }
        }));
        final int i10 = 0;
        d0().s.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(22, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.match.activity.a
            public final /* synthetic */ MatchActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object v) throws Throwable {
                /*
                    Method dump skipped, instructions count: 1738
                    To view this dump add '--comments-level debug' option
                */
                throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.match.activity.a.invoke(java.lang.Object):java.lang.Object");
            }
        }));
        d0().t.f(this, new com.quizlet.ads.ui.fragments.c(this, 17));
        d0().v.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(22, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.match.activity.a
            public final /* synthetic */ MatchActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object v) throws Throwable {
                /*
                    Method dump skipped, instructions count: 1738
                    To view this dump add '--comments-level debug' option
                */
                throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.match.activity.a.invoke(java.lang.Object):java.lang.Object");
            }
        }));
        d0().u.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(22, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.match.activity.a
            public final /* synthetic */ MatchActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object v) throws Throwable {
                /*
                    Method dump skipped, instructions count: 1738
                    To view this dump add '--comments-level debug' option
                */
                throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.match.activity.a.invoke(java.lang.Object):java.lang.Object");
            }
        }));
        d0.i.f.a(d0());
    }

    @Override // com.quizlet.baseui.base.b, android.app.Activity
    public final boolean onOptionsItemSelected(MenuItem item) {
        Intrinsics.checkNotNullParameter(item, "item");
        int itemId = item.getItemId();
        if (itemId == R.id.menu_study_mode_settings) {
            g gVarD0 = d0();
            boolean z = gVarD0.m.d() instanceof com.quizlet.features.match.data.V;
            j jVar = gVarD0.i;
            jVar.getClass();
            io.reactivex.rxjava3.internal.operators.single.g gVarG = ((r) jVar.d).g(new com.quizlet.features.match.game.a(jVar, z));
            Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
            io.reactivex.rxjava3.internal.observers.e eVarI = gVarG.i(new com.quizlet.quizletandroid.ui.setpage.terms.c(gVarD0.t, 8), io.reactivex.rxjava3.internal.functions.d.e);
            Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
            Intrinsics.checkNotNullParameter(eVarI, "<this>");
            gVarD0.A(eVarI);
            return true;
        }
        if (itemId != R.id.menu_audio) {
            return super.onOptionsItemSelected(item);
        }
        g gVarD02 = d0();
        Y y = gVarD02.v;
        Boolean bool = (Boolean) y.d();
        if (bool != null) {
            boolean zBooleanValue = bool.booleanValue();
            boolean z2 = !zBooleanValue;
            y.l(Boolean.valueOf(z2));
            assistantMode.refactored.a.p(gVarD02.d.a, "PREF_MATCH_PLAY_AUDIO", z2);
            if (!zBooleanValue) {
                Y y2 = gVarD02.m;
                if (!Intrinsics.b(y2.d(), com.quizlet.features.match.data.d0.a)) {
                    gVarD02.B((AbstractC4368y) y2.d());
                    return true;
                }
            }
            gVarD02.D();
        }
        return true;
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, android.app.Activity
    public final void onPostCreate(Bundle bundle) {
        super.onPostCreate(bundle);
        v((Toolbar) ((C4604h) K()).b.d);
        com.bumptech.glide.c cVarR = r();
        if (cVarR != null) {
            cVarR.u(false);
            cVarR.s(true);
            cVarR.w();
            cVarR.v(com.quizlet.themes.extensions.a.d(this, R.drawable.ic_sys_close_x, android.R.attr.colorControlNormal));
        }
    }

    @Override // android.app.Activity
    public final boolean onPrepareOptionsMenu(Menu menu) {
        Intrinsics.checkNotNullParameter(menu, "menu");
        super.onPrepareOptionsMenu(menu);
        MenuItem menuItemFindItem = menu.findItem(R.id.menu_study_mode_settings);
        if (menuItemFindItem != null) {
            menuItemFindItem.setIcon(com.quizlet.themes.extensions.a.d(this, R.drawable.ic_sys_settings_24dp, android.R.attr.colorControlNormal));
        }
        this.q = menu.findItem(R.id.menu_audio);
        Boolean bool = (Boolean) d0().v.d();
        if (bool != null ? bool.booleanValue() : true) {
            MenuItem menuItem = this.q;
            if (menuItem != null) {
                menuItem.setIcon(com.facebook.appevents.g.f(this, R.drawable.ic_sys_audio));
                return true;
            }
        } else {
            MenuItem menuItem2 = this.q;
            if (menuItem2 != null) {
                menuItem2.setIcon(com.facebook.appevents.g.f(this, R.drawable.ic_sys_audio_off));
            }
        }
        return true;
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onStart() {
        super.onStart();
        g gVarD0 = d0();
        com.quizlet.features.infra.basestudy.manager.f.h(gVarD0.j.a);
        io.reactivex.rxjava3.internal.observers.e eVarI = gVarD0.c.u().i(new com.quizlet.quizletandroid.ui.setpage.terms.c(gVarD0, 7), io.reactivex.rxjava3.internal.functions.d.e);
        Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
        Intrinsics.checkNotNullParameter(eVarI, "<this>");
        gVarD0.A(eVarI);
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onStop() {
        com.quizlet.features.infra.basestudy.manager.f.i(d0().j.a);
        super.onStop();
    }
}

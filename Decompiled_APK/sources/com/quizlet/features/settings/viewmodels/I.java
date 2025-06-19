package com.quizlet.features.settings.viewmodels;

import android.content.SharedPreferences;
import androidx.appcompat.app.AbstractC0061q;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import androidx.paging.C1329n;
import com.quizlet.data.model.C4184z;
import com.quizlet.data.model.EnumC4167t0;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class I extends w0 implements p, com.quizlet.features.infra.logout.viewmodels.a {
    public final com.quizlet.quizletandroid.interactor.t b;
    public final com.quizlet.billing.model.a c;
    public final com.quizlet.billing.subscriptions.i d;
    public final com.facebook.z e;
    public final com.quizlet.data.repository.set.f f;
    public final C4184z g;
    public final com.quizlet.features.emailconfirmation.logging.a h;
    public final com.quizlet.features.infra.logout.viewmodels.d i;
    public final com.lyft.android.scissors.b j;
    public final com.google.android.material.floatingactionbutton.c k;
    public final com.quizlet.data.repository.user.a l;
    public final AbstractC5040y m;
    public final s0 n;
    public final C1329n o;
    public final d0 p;

    public I(com.quizlet.quizletandroid.interactor.t loggedInUserInteractor, com.quizlet.billing.model.a billingInventory, com.quizlet.billing.subscriptions.i subscriptionLookup, com.facebook.z offlineSettingsState, com.quizlet.data.repository.set.f nightThemeManager, C4184z buildConfig, com.quizlet.features.emailconfirmation.logging.a settingsEventLogger, com.quizlet.features.infra.logout.viewmodels.d logoutViewModelDelegate, com.lyft.android.scissors.b saveSoundEffectsPreferenceUseCase, com.google.android.material.floatingactionbutton.c getCurrentSoundEffectsPreferenceUseCase, com.quizlet.data.repository.user.a oneTrustPreferencesSettingFeature, AbstractC5040y dispatcher) {
        s0 s0Var;
        Object value;
        Object value2;
        Intrinsics.checkNotNullParameter(loggedInUserInteractor, "loggedInUserInteractor");
        Intrinsics.checkNotNullParameter(billingInventory, "billingInventory");
        Intrinsics.checkNotNullParameter(subscriptionLookup, "subscriptionLookup");
        Intrinsics.checkNotNullParameter(offlineSettingsState, "offlineSettingsState");
        Intrinsics.checkNotNullParameter(nightThemeManager, "nightThemeManager");
        Intrinsics.checkNotNullParameter(buildConfig, "buildConfig");
        Intrinsics.checkNotNullParameter(settingsEventLogger, "settingsEventLogger");
        Intrinsics.checkNotNullParameter(logoutViewModelDelegate, "logoutViewModelDelegate");
        Intrinsics.checkNotNullParameter(saveSoundEffectsPreferenceUseCase, "saveSoundEffectsPreferenceUseCase");
        Intrinsics.checkNotNullParameter(getCurrentSoundEffectsPreferenceUseCase, "getCurrentSoundEffectsPreferenceUseCase");
        Intrinsics.checkNotNullParameter(oneTrustPreferencesSettingFeature, "oneTrustPreferencesSettingFeature");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = loggedInUserInteractor;
        this.c = billingInventory;
        this.d = subscriptionLookup;
        this.e = offlineSettingsState;
        this.f = nightThemeManager;
        this.g = buildConfig;
        this.h = settingsEventLogger;
        this.i = logoutViewModelDelegate;
        this.j = saveSoundEffectsPreferenceUseCase;
        this.k = getCurrentSoundEffectsPreferenceUseCase;
        this.l = oneTrustPreferencesSettingFeature;
        this.m = dispatcher;
        s0 s0VarC = e0.c(new com.quizlet.features.settings.data.states.y((8191 & 1) != 0 ? "" : "GuiFranco57", (8191 & 2) != 0 ? "" : "guilherme.franco@quizlet.com", false, false, com.quizlet.features.settings.data.models.f.b, new com.quizlet.features.settings.data.models.i(R.string.upgrade_now_button), com.quizlet.features.settings.data.models.d.a, com.quizlet.themes.nighttheme.a.c, (8191 & 256) == 0, (8191 & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) != 0, "", false, false));
        this.n = s0VarC;
        this.o = new C1329n(s0VarC, 2);
        this.p = e0.b(0, 1, null, 5);
        kotlinx.coroutines.E.A(p0.j(this), null, null, new C(this, null), 3);
        com.quizlet.themes.nighttheme.a aVarN = nightThemeManager.n();
        do {
            s0Var = this.n;
            value = s0Var.getValue();
        } while (!s0Var.k(value, com.quizlet.features.settings.data.states.y.a((com.quizlet.features.settings.data.states.y) value, null, null, false, false, null, null, null, aVarN, false, false, null, false, 8063)));
        this.g.getClass();
        String str = "9.34.3 (" + ((Object) 2601637) + ")";
        do {
            value2 = s0Var.getValue();
        } while (!s0Var.k(value2, com.quizlet.features.settings.data.states.y.a((com.quizlet.features.settings.data.states.y) value2, null, null, false, false, null, null, null, null, false, false, str, false, 5119)));
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x005f A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:18:0x0060  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0083  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x001a  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:18:0x0060 -> B:19:0x0062). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object A(com.quizlet.features.settings.viewmodels.I r22, kotlin.coroutines.jvm.internal.c r23) {
        /*
            r0 = r22
            r1 = r23
            r0.getClass()
            boolean r2 = r1 instanceof com.quizlet.features.settings.viewmodels.w
            if (r2 == 0) goto L1a
            r2 = r1
            com.quizlet.features.settings.viewmodels.w r2 = (com.quizlet.features.settings.viewmodels.w) r2
            int r3 = r2.p
            r4 = -2147483648(0xffffffff80000000, float:-0.0)
            r5 = r3 & r4
            if (r5 == 0) goto L1a
            int r3 = r3 - r4
            r2.p = r3
            goto L1f
        L1a:
            com.quizlet.features.settings.viewmodels.w r2 = new com.quizlet.features.settings.viewmodels.w
            r2.<init>(r0, r1)
        L1f:
            java.lang.Object r1 = r2.n
            kotlin.coroutines.intrinsics.a r3 = kotlin.coroutines.intrinsics.a.a
            int r4 = r2.p
            r5 = 1
            if (r4 == 0) goto L40
            if (r4 != r5) goto L38
            com.quizlet.features.settings.data.states.y r0 = r2.m
            java.lang.Object r4 = r2.l
            kotlinx.coroutines.flow.s0 r6 = r2.k
            com.quizlet.features.settings.viewmodels.I r7 = r2.j
            androidx.glance.appwidget.protobuf.Z.e(r1)
            r8 = r0
            r0 = r7
            goto L62
        L38:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r1 = "call to 'resume' before 'invoke' with coroutine"
            r0.<init>(r1)
            throw r0
        L40:
            androidx.glance.appwidget.protobuf.Z.e(r1)
            kotlinx.coroutines.flow.s0 r1 = r0.n
            r6 = r1
        L46:
            java.lang.Object r4 = r6.getValue()
            r1 = r4
            com.quizlet.features.settings.data.states.y r1 = (com.quizlet.features.settings.data.states.y) r1
            com.quizlet.data.repository.user.a r7 = r0.l
            r2.j = r0
            r2.k = r6
            r2.l = r4
            r2.m = r1
            r2.p = r5
            java.lang.Object r7 = r7.j(r2)
            if (r7 != r3) goto L60
            return r3
        L60:
            r8 = r1
            r1 = r7
        L62:
            java.lang.Boolean r1 = (java.lang.Boolean) r1
            boolean r20 = r1.booleanValue()
            r18 = 0
            r21 = 4095(0xfff, float:5.738E-42)
            r9 = 0
            r10 = 0
            r11 = 0
            r12 = 0
            r13 = 0
            r14 = 0
            r15 = 0
            r16 = 0
            r17 = 0
            r19 = 0
            com.quizlet.features.settings.data.states.y r1 = com.quizlet.features.settings.data.states.y.a(r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18, r19, r20, r21)
            boolean r1 = r6.k(r4, r1)
            if (r1 == 0) goto L46
            kotlin.Unit r0 = kotlin.Unit.a
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.settings.viewmodels.I.A(com.quizlet.features.settings.viewmodels.I, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:19:0x0058, code lost:
    
        if (r1 == r3) goto L24;
     */
    /* JADX WARN: Code restructure failed: missing block: B:23:0x006c, code lost:
    
        if (r1 == r3) goto L24;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x001a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object B(com.quizlet.features.settings.viewmodels.I r17, int r18, kotlin.coroutines.jvm.internal.c r19) {
        /*
            r0 = r17
            r1 = r19
            r0.getClass()
            boolean r2 = r1 instanceof com.quizlet.features.settings.viewmodels.x
            if (r2 == 0) goto L1a
            r2 = r1
            com.quizlet.features.settings.viewmodels.x r2 = (com.quizlet.features.settings.viewmodels.x) r2
            int r3 = r2.m
            r4 = -2147483648(0xffffffff80000000, float:-0.0)
            r5 = r3 & r4
            if (r5 == 0) goto L1a
            int r3 = r3 - r4
            r2.m = r3
            goto L1f
        L1a:
            com.quizlet.features.settings.viewmodels.x r2 = new com.quizlet.features.settings.viewmodels.x
            r2.<init>(r0, r1)
        L1f:
            java.lang.Object r1 = r2.k
            kotlin.coroutines.intrinsics.a r3 = kotlin.coroutines.intrinsics.a.a
            int r4 = r2.m
            r5 = 2
            r6 = 1
            if (r4 == 0) goto L41
            if (r4 == r6) goto L3b
            if (r4 != r5) goto L33
            com.quizlet.features.settings.viewmodels.I r0 = r2.j
            androidx.glance.appwidget.protobuf.Z.e(r1)
            goto L6f
        L33:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r1 = "call to 'resume' before 'invoke' with coroutine"
            r0.<init>(r1)
            throw r0
        L3b:
            com.quizlet.features.settings.viewmodels.I r0 = r2.j
            androidx.glance.appwidget.protobuf.Z.e(r1)
            goto L5b
        L41:
            androidx.glance.appwidget.protobuf.Z.e(r1)
            com.quizlet.billing.subscriptions.i r1 = r0.d
            r4 = r18
            if (r4 != r6) goto L5e
            com.quizlet.billing.subscriptions.j r4 = com.quizlet.billing.subscriptions.j.c
            io.reactivex.rxjava3.internal.operators.maybe.h r1 = r1.a(r4)
            r2.j = r0
            r2.m = r6
            java.lang.Object r1 = com.google.android.gms.internal.mlkit_vision_camera.I1.e(r1, r2)
            if (r1 != r3) goto L5b
            goto L6e
        L5b:
            com.quizlet.data.model.billing.a r1 = (com.quizlet.data.model.billing.a) r1
            goto L71
        L5e:
            com.quizlet.billing.subscriptions.j r4 = com.quizlet.billing.subscriptions.j.b
            io.reactivex.rxjava3.internal.operators.maybe.h r1 = r1.a(r4)
            r2.j = r0
            r2.m = r5
            java.lang.Object r1 = com.google.android.gms.internal.mlkit_vision_camera.I1.e(r1, r2)
            if (r1 != r3) goto L6f
        L6e:
            return r3
        L6f:
            com.quizlet.data.model.billing.a r1 = (com.quizlet.data.model.billing.a) r1
        L71:
            if (r1 == 0) goto L7d
            boolean r1 = r1.a()
            if (r1 != r6) goto L7d
            r1 = 2132019776(0x7f140a40, float:1.9677896E38)
            goto L80
        L7d:
            r1 = 2132020025(0x7f140b39, float:1.9678401E38)
        L80:
            kotlinx.coroutines.flow.s0 r0 = r0.n
        L82:
            java.lang.Object r2 = r0.getValue()
            r3 = r2
            com.quizlet.features.settings.data.states.y r3 = (com.quizlet.features.settings.data.states.y) r3
            com.quizlet.features.settings.data.models.i r9 = new com.quizlet.features.settings.data.models.i
            r9.<init>(r1)
            r14 = 0
            r16 = 8159(0x1fdf, float:1.1433E-41)
            r4 = 0
            r5 = 0
            r6 = 0
            r7 = 0
            r8 = 0
            r10 = 0
            r11 = 0
            r12 = 0
            r13 = 0
            r15 = 0
            com.quizlet.features.settings.data.states.y r3 = com.quizlet.features.settings.data.states.y.a(r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16)
            boolean r2 = r0.k(r2, r3)
            if (r2 == 0) goto L82
            kotlin.Unit r0 = kotlin.Unit.a
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.settings.viewmodels.I.B(com.quizlet.features.settings.viewmodels.I, int, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final void C(com.quizlet.themes.nighttheme.a aVar) {
        int i;
        String str;
        I i2 = this;
        com.quizlet.themes.nighttheme.a nightThemeMode = aVar;
        Intrinsics.checkNotNullParameter(nightThemeMode, "themeMode");
        com.quizlet.data.repository.set.f fVar = i2.f;
        fVar.getClass();
        Intrinsics.checkNotNullParameter(nightThemeMode, "nightThemeMode");
        ((SharedPreferences) fVar.c).edit().putInt("CUR_THEME", nightThemeMode.a).apply();
        int iOrdinal = fVar.n().ordinal();
        if (iOrdinal == 0) {
            i = -1;
        } else if (iOrdinal == 1) {
            i = 1;
        } else {
            if (iOrdinal != 2) {
                throw new NoWhenBranchMatchedException();
            }
            i = 2;
        }
        AbstractC0061q.k(i);
        int iOrdinal2 = nightThemeMode.ordinal();
        if (iOrdinal2 == 0) {
            str = "toggle_night_theme_setting_system_default";
        } else if (iOrdinal2 == 1) {
            str = "toggle_night_theme_setting_off";
        } else {
            if (iOrdinal2 != 2) {
                throw new NoWhenBranchMatchedException();
            }
            str = "toggle_night_theme_setting_on";
        }
        ((EventLogger) fVar.d).I(str);
        while (true) {
            s0 s0Var = i2.n;
            Object value = s0Var.getValue();
            if (s0Var.k(value, com.quizlet.features.settings.data.states.y.a((com.quizlet.features.settings.data.states.y) value, null, null, false, false, null, null, null, nightThemeMode, false, false, null, false, 8063))) {
                return;
            }
            i2 = this;
            nightThemeMode = aVar;
        }
    }

    @Override // com.quizlet.features.infra.logout.viewmodels.a
    public final void v(EnumC4167t0 warningType) {
        Intrinsics.checkNotNullParameter(warningType, "warningType");
        this.i.v(warningType);
    }

    @Override // androidx.lifecycle.w0
    public final void z() {
        kotlinx.coroutines.E.h(this.i.b, null);
    }
}

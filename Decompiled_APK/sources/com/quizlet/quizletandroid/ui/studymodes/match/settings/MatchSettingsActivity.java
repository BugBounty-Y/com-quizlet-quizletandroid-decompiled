package com.quizlet.quizletandroid.ui.studymodes.match.settings;

import android.os.Bundle;
import android.os.Parcelable;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import androidx.activity.v;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3188k6;
import com.quizlet.features.infra.basestudy.data.models.logging.StudyEventLogData;
import com.quizlet.features.match.settings.MatchSettingsData;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.l0;
import com.quizlet.quizletandroid.ui.common.adapter.viewholder.h;
import java.util.ArrayList;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class MatchSettingsActivity extends com.quizlet.ads.ui.activity.d {
    public static final String q;

    static {
        Intrinsics.checkNotNullExpressionValue("MatchSettingsActivity", "getSimpleName(...)");
        q = "MatchSettingsActivity";
    }

    public MatchSettingsActivity() {
        super(11);
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return q;
    }

    @Override // com.quizlet.baseui.base.f
    public final androidx.viewbinding.a N() {
        l0 l0VarA = l0.a(getLayoutInflater());
        Intrinsics.checkNotNullExpressionValue(l0VarA, "inflate(...)");
        return l0VarA;
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x0041  */
    @Override // androidx.activity.s, android.app.Activity
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onBackPressed() {
        /*
            r5 = this;
            androidx.fragment.app.h0 r0 = r5.getSupportFragmentManager()
            java.lang.String r1 = com.quizlet.quizletandroid.ui.studymodes.match.settings.MatchSettingsFragment.k
            androidx.fragment.app.Fragment r0 = r0.E(r1)
            com.quizlet.quizletandroid.ui.studymodes.match.settings.MatchSettingsFragment r0 = (com.quizlet.quizletandroid.ui.studymodes.match.settings.MatchSettingsFragment) r0
            if (r0 == 0) goto L4e
            com.onetrust.otpublishers.headless.UI.TVUI.datautils.a r0 = r0.W()
            java.lang.Object r1 = r0.c
            com.quizlet.quizletandroid.ui.studymodes.match.settings.MatchSettingsFragment r1 = (com.quizlet.quizletandroid.ui.studymodes.match.settings.MatchSettingsFragment) r1
            r2 = 0
            java.lang.String r3 = "view"
            if (r1 == 0) goto L4a
            com.quizlet.features.match.settings.MatchSettingsData r1 = r1.T()
            com.quizlet.features.match.settings.MatchSettingsData r1 = r0.f(r1)
            java.lang.Object r4 = r0.c
            com.quizlet.quizletandroid.ui.studymodes.match.settings.MatchSettingsFragment r4 = (com.quizlet.quizletandroid.ui.studymodes.match.settings.MatchSettingsFragment) r4
            if (r4 == 0) goto L46
            boolean r3 = r0.a
            if (r3 == 0) goto L41
            java.lang.Object r0 = r0.d
            com.quizlet.features.match.settings.MatchSettingsData r0 = (com.quizlet.features.match.settings.MatchSettingsData) r0
            if (r0 == 0) goto L3b
            boolean r0 = r0.equals(r1)
            if (r0 != 0) goto L41
            r0 = 1
            goto L42
        L3b:
            java.lang.String r0 = "initialSettings"
            kotlin.jvm.internal.Intrinsics.m(r0)
            throw r2
        L41:
            r0 = 0
        L42:
            r4.Y(r1, r0)
            goto L4e
        L46:
            kotlin.jvm.internal.Intrinsics.m(r3)
            throw r2
        L4a:
            kotlin.jvm.internal.Intrinsics.m(r3)
            throw r2
        L4e:
            super.onBackPressed()
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.match.settings.MatchSettingsActivity.onBackPressed():void");
    }

    @Override // com.quizlet.ads.ui.activity.d, com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        v.b(this, null, 3);
        LinearLayout linearLayout = ((l0) K()).a;
        Intrinsics.checkNotNullExpressionValue(linearLayout, "getRoot(...)");
        AbstractC3188k6.a(linearLayout);
        AbstractC1136h0 supportFragmentManager = getSupportFragmentManager();
        String str = MatchSettingsFragment.k;
        if (((MatchSettingsFragment) supportFragmentManager.E(str)) == null) {
            Parcelable parcelableExtra = getIntent().getParcelableExtra("com.quizlet.quizletandroid.ui.studymodes.match.CurrentSettings");
            if (parcelableExtra == null) {
                throw new IllegalArgumentException("Required value was null.");
            }
            MatchSettingsData currentSettings = (MatchSettingsData) parcelableExtra;
            int intExtra = getIntent().getIntExtra("com.quizlet.quizletandroid.ui.studymodes.match.SelectedTermCount", 0);
            ArrayList<Integer> availableTermSides = getIntent().getIntegerArrayListExtra("com.quizlet.quizletandroid.ui.studymodes.match.AvailableTermSides");
            if (availableTermSides == null) {
                availableTermSides = new ArrayList<>();
            }
            boolean booleanExtra = getIntent().getBooleanExtra("com.quizlet.quizletandroid.ui.studymodes.match.IsMatchRunning", false);
            Parcelable parcelableExtra2 = getIntent().getParcelableExtra("com.quizlet.quizletandroid.ui.studymodes.match.StudyEventLogData");
            if (parcelableExtra2 == null) {
                throw new IllegalArgumentException("Required value was null.");
            }
            StudyEventLogData studyEventLogData = (StudyEventLogData) parcelableExtra2;
            Intrinsics.checkNotNullParameter(currentSettings, "currentSettings");
            Intrinsics.checkNotNullParameter(availableTermSides, "availableTermSides");
            Intrinsics.checkNotNullParameter(studyEventLogData, "studyEventLogData");
            MatchSettingsFragment matchSettingsFragment = new MatchSettingsFragment();
            Bundle bundle2 = new Bundle();
            bundle2.putParcelable("currentSettings", currentSettings);
            bundle2.putInt("selectedTermCount", intExtra);
            bundle2.putIntegerArrayList("availableTermSides", availableTermSides);
            bundle2.putBoolean("isMatchRunning", booleanExtra);
            bundle2.putParcelable("studyEventLogData", studyEventLogData);
            matchSettingsFragment.setArguments(bundle2);
            AbstractC1136h0 supportFragmentManager2 = getSupportFragmentManager();
            supportFragmentManager2.getClass();
            C1121a c1121a = new C1121a(supportFragmentManager2);
            c1121a.l(R.id.fragment_container, matchSettingsFragment, str);
            c1121a.g();
        }
        ((FrameLayout) ((l0) K()).c.c).setOnClickListener(new h(this, 16));
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, android.app.Activity
    public final void onPostCreate(Bundle bundle) {
        super.onPostCreate(bundle);
        setTitle(R.string.study_mode_options);
    }
}

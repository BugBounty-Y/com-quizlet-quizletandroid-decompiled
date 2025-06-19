package com.quizlet.features.onboarding.survey;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import com.quizlet.quizletandroid.R;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class m {
    public static final m b;
    public static final m c;
    public static final /* synthetic */ m[] d;
    public static final /* synthetic */ kotlin.enums.b e;
    public final int a;

    static {
        m mVar = new m("None", 0, R.string.onboarding_survey_source_none);
        b = mVar;
        m mVar2 = new m("Teacher", 1, R.string.onboarding_survey_source_teacher);
        m mVar3 = new m("FriendOrFamily", 2, R.string.onboarding_survey_source_friend_or_family);
        m mVar4 = new m("TikTok", 3, R.string.onboarding_survey_source_tiktok);
        m mVar5 = new m("FacebookOrInstagram", 4, R.string.onboarding_survey_source_facebook_or_instagram);
        m mVar6 = new m("YouTube", 5, R.string.onboarding_survey_source_youtube);
        m mVar7 = new m("GoogleSearch", 6, R.string.onboarding_survey_source_google_search);
        m mVar8 = new m("PlayStore", 7, R.string.onboarding_survey_source_play_store);
        m mVar9 = new m("Other", 8, R.string.onboarding_survey_source_other);
        c = mVar9;
        m[] mVarArr = {mVar, mVar2, mVar3, mVar4, mVar5, mVar6, mVar7, mVar8, mVar9};
        d = mVarArr;
        e = AbstractC3328d.f(mVarArr);
    }

    public m(String str, int i, int i2) {
        this.a = i2;
    }

    public static m valueOf(String str) {
        return (m) Enum.valueOf(m.class, str);
    }

    public static m[] values() {
        return (m[]) d.clone();
    }
}

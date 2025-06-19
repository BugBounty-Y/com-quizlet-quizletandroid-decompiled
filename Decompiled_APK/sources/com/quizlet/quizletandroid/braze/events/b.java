package com.quizlet.quizletandroid.braze.events;

import android.content.SharedPreferences;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.core.J0;
import com.braze.Braze;
import com.braze.models.outgoing.BrazeProperties;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.features.userprofile.ui.UserProfileFragment;
import com.quizlet.quizletandroid.ui.profile.ProfileFragment;
import com.quizlet.quizletandroid.ui.startpage.nav2.OldHomeFragment;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public static final long d = TimeUnit.DAYS.toMillis(1);
    public static final Set e;
    public final com.quizlet.data.interactor.course.a a;
    public final com.quizlet.db.b b;
    public final UserInfoCache c;

    static {
        String str = OldHomeFragment.d1;
        String str2 = ProfileFragment.x;
        String str3 = ProfileFragment.x;
        String str4 = UserProfileFragment.k;
        String[] elements = {str, str3, UserProfileFragment.k};
        Intrinsics.checkNotNullParameter(elements, "elements");
        e = C4933y.T(elements);
    }

    public b(com.quizlet.data.interactor.course.a brazeEventLogger, com.quizlet.db.b brazeEventSharedPreferences, UserInfoCache userInfoCache) {
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        Intrinsics.checkNotNullParameter(brazeEventLogger, "brazeEventLogger");
        Intrinsics.checkNotNullParameter(brazeEventSharedPreferences, "brazeEventSharedPreferences");
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        this.a = brazeEventLogger;
        this.b = brazeEventSharedPreferences;
        this.c = userInfoCache;
    }

    public final void a(String screen) {
        J0 event;
        long j;
        Intrinsics.checkNotNullParameter(screen, "screen");
        if (e.contains(screen)) {
            if (Intrinsics.b(screen, OldHomeFragment.d1)) {
                Intrinsics.checkNotNullParameter("homepage_view", "name");
                event = new e(9);
            } else if (Intrinsics.b(screen, ProfileFragment.x)) {
                Intrinsics.checkNotNullParameter("account_page_view_app", "name");
                event = new d(9);
            } else {
                if (!Intrinsics.b(screen, UserProfileFragment.k)) {
                    throw new IllegalStateException(AbstractC0147y.d("Screen has not been allowlisted: ", screen));
                }
                Intrinsics.checkNotNullParameter("view_profile", "name");
                event = new f(9);
            }
            boolean z = event instanceof e;
            SharedPreferences sharedPreferences = this.b.a;
            if (z) {
                j = sharedPreferences.getLong("PREF_VIEW_HOME_TIMESTAMP", 0L);
            } else if (event instanceof d) {
                j = sharedPreferences.getLong("PREF_VIEW_ACCOUNT_TIMESTAMP", 0L);
            } else {
                if (!(event instanceof f)) {
                    throw new IllegalStateException("Event has not been allowlisted: ".concat(event.getClass().getSimpleName()));
                }
                j = sharedPreferences.getLong("PREF_VIEW_PROFILE_TIMESTAMP", 0L);
            }
            long jCurrentTimeMillis = System.currentTimeMillis() - j;
            if (!this.c.b() || jCurrentTimeMillis < d) {
                return;
            }
            com.quizlet.data.interactor.course.a aVar = this.a;
            Intrinsics.checkNotNullParameter(event, "event");
            ((Braze) aVar.b).logCustomEvent(event.z(), (BrazeProperties) event.b);
            if (z) {
                sharedPreferences.edit().putLong("PREF_VIEW_HOME_TIMESTAMP", System.currentTimeMillis()).apply();
            } else if (event instanceof d) {
                sharedPreferences.edit().putLong("PREF_VIEW_ACCOUNT_TIMESTAMP", System.currentTimeMillis()).apply();
            } else {
                if (!(event instanceof f)) {
                    throw new IllegalStateException("Event has not been allowlisted: ".concat(event.getClass().getSimpleName()));
                }
                sharedPreferences.edit().putLong("PREF_VIEW_PROFILE_TIMESTAMP", System.currentTimeMillis()).apply();
            }
        }
    }
}

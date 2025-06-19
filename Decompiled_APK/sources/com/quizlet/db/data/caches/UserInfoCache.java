package com.quizlet.db.data.caches;

import android.content.SharedPreferences;
import android.util.Base64;
import com.quizlet.data.repository.user.b;
import com.quizlet.db.token.a;
import com.quizlet.quizletandroid.R;
import java.nio.charset.Charset;
import java.util.UUID;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import org.jetbrains.annotations.NotNull;
import timber.log.c;

@Metadata
/* loaded from: classes2.dex */
public final class UserInfoCache implements b {

    @NotNull
    private static final String CLIENT_DEVICE_ID = "client_device_id";

    @NotNull
    private static final String ENCODED_PERSON_ID_KEY = "ps";

    @NotNull
    private static final String ENCODED_PROFILE_IMAGE_KEY = "pl";

    @NotNull
    private static final String ENCODED_USERNAME_KEY = "ue";

    @NotNull
    private static final String HAS_LOGGED_IN_KEY = "has_logged_in";

    @NotNull
    private static final String PERSON_ID_LONG_PREFS_KEY = "person_id_long";

    @NotNull
    private static final String PROFILE_IMAGE_PREFS_KEY = "profile_image";

    @NotNull
    private static final String USERNAME_PREFS_KEY = "username";

    @NotNull
    private static final String USER_BADGE_TEXT_RES_ID_PREFS_KEY = "user_badge_text_res_id";

    @NotNull
    private final a accessTokenProvider;

    @NotNull
    private final SharedPreferences sharedPreferences;

    @Metadata
    public static final class Companion {
    }

    public UserInfoCache(SharedPreferences sharedPreferences, a accessTokenProvider) {
        Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
        Intrinsics.checkNotNullParameter(accessTokenProvider, "accessTokenProvider");
        this.sharedPreferences = sharedPreferences;
        this.accessTokenProvider = accessTokenProvider;
    }

    public final String a(String str, String str2) {
        if (this.sharedPreferences.contains(str)) {
            String string = this.sharedPreferences.getString(str, null);
            if (string != null) {
                SharedPreferences.Editor editorRemove = this.sharedPreferences.edit().remove(str);
                byte[] bytes = string.getBytes(Charsets.UTF_8);
                Intrinsics.checkNotNullExpressionValue(bytes, "getBytes(...)");
                editorRemove.putString(str2, Base64.encodeToString(bytes, 0)).apply();
                return string;
            }
        } else if (this.sharedPreferences.getString(str2, null) != null) {
            byte[] bArrDecode = Base64.decode(this.sharedPreferences.getString(str2, null), 0);
            Intrinsics.checkNotNullExpressionValue(bArrDecode, "decode(...)");
            return new String(bArrDecode, Charsets.UTF_8);
        }
        return null;
    }

    public final boolean b() {
        String strA = this.accessTokenProvider.a();
        return strA != null && strA.length() > 0;
    }

    public final void c(long j, String str, String str2, Integer num) {
        String strEncodeToString;
        String strValueOf = String.valueOf(j);
        Charset charset = Charsets.UTF_8;
        byte[] bytes = strValueOf.getBytes(charset);
        Intrinsics.checkNotNullExpressionValue(bytes, "getBytes(...)");
        String strEncodeToString2 = Base64.encodeToString(bytes, 0);
        String strEncodeToString3 = null;
        if (str == null) {
            strEncodeToString = null;
        } else {
            byte[] bytes2 = str.getBytes(charset);
            Intrinsics.checkNotNullExpressionValue(bytes2, "getBytes(...)");
            strEncodeToString = Base64.encodeToString(bytes2, 0);
        }
        if (str2 != null) {
            byte[] bytes3 = str2.getBytes(charset);
            Intrinsics.checkNotNullExpressionValue(bytes3, "getBytes(...)");
            strEncodeToString3 = Base64.encodeToString(bytes3, 0);
        }
        this.sharedPreferences.edit().putString(ENCODED_USERNAME_KEY, strEncodeToString).putString(ENCODED_PERSON_ID_KEY, strEncodeToString2).putString(ENCODED_PROFILE_IMAGE_KEY, strEncodeToString3).putInt(USER_BADGE_TEXT_RES_ID_PREFS_KEY, num != null ? num.intValue() : R.string.empty).apply();
    }

    public final void d() {
        assistantMode.refactored.a.p(this.sharedPreferences, HAS_LOGGED_IN_KEY, true);
    }

    @Override // com.quizlet.data.repository.user.b
    @NotNull
    public UUID getDeviceId() {
        UUID uuidFromString;
        String string = this.sharedPreferences.getString(CLIENT_DEVICE_ID, null);
        UUID uuidRandomUUID = UUID.randomUUID();
        if (string != null) {
            try {
                uuidFromString = UUID.fromString(string);
            } catch (IllegalArgumentException e) {
                c.a.f(e, "Bad format for stored deviceId", new Object[0]);
                uuidFromString = uuidRandomUUID;
            }
            Intrinsics.d(uuidFromString);
        } else {
            Intrinsics.d(uuidRandomUUID);
            uuidFromString = uuidRandomUUID;
        }
        if (uuidFromString.equals(uuidRandomUUID)) {
            this.sharedPreferences.edit().putString(CLIENT_DEVICE_ID, uuidFromString.toString()).apply();
        }
        return uuidFromString;
    }

    @Override // com.quizlet.data.repository.user.b
    public boolean getHasLoggedInBefore() {
        return this.sharedPreferences.getBoolean(HAS_LOGGED_IN_KEY, false);
    }

    @Override // com.quizlet.data.repository.user.b
    public long getPersonId() throws NumberFormatException {
        if (this.sharedPreferences.contains(PERSON_ID_LONG_PREFS_KEY)) {
            long j = this.sharedPreferences.getLong(PERSON_ID_LONG_PREFS_KEY, 0L);
            SharedPreferences.Editor editorRemove = this.sharedPreferences.edit().remove(PERSON_ID_LONG_PREFS_KEY);
            byte[] bytes = String.valueOf(j).getBytes(Charsets.UTF_8);
            Intrinsics.checkNotNullExpressionValue(bytes, "getBytes(...)");
            editorRemove.putString(ENCODED_PERSON_ID_KEY, Base64.encodeToString(bytes, 0)).apply();
            return j;
        }
        if (this.sharedPreferences.getString(ENCODED_PERSON_ID_KEY, null) == null) {
            return 0L;
        }
        byte[] bArrDecode = Base64.decode(this.sharedPreferences.getString(ENCODED_PERSON_ID_KEY, null), 0);
        Intrinsics.d(bArrDecode);
        Long lValueOf = Long.valueOf(new String(bArrDecode, Charsets.UTF_8));
        Intrinsics.d(lValueOf);
        return lValueOf.longValue();
    }

    @Override // com.quizlet.data.repository.user.b
    public String getProfileImage() {
        return a(PROFILE_IMAGE_PREFS_KEY, ENCODED_PROFILE_IMAGE_KEY);
    }

    @Override // com.quizlet.data.repository.user.b
    public int getUserBadgeStringResId() {
        return this.sharedPreferences.getInt(USER_BADGE_TEXT_RES_ID_PREFS_KEY, R.string.empty);
    }

    @Override // com.quizlet.data.repository.user.b
    public String getUsername() {
        return a("username", ENCODED_USERNAME_KEY);
    }
}

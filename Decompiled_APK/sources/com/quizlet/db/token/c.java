package com.quizlet.db.token;

import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.util.Base64;
import com.braze.requests.framework.o;
import com.google.firebase.crashlytics.internal.common.i;
import com.google.firebase.crashlytics.internal.common.q;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Collections;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;

/* loaded from: classes2.dex */
public final class c implements a {
    public final SharedPreferences a;
    public final b b;
    public final com.google.firebase.crashlytics.b c;
    public final u d;
    public final u e;
    public String f;
    public final SharedPreferences g;
    public final b h;

    public c(SharedPreferences sharedPreferences, b sharedPreferencesAccessTokenProvider, com.google.firebase.crashlytics.b firebaseCrashlytics) {
        Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
        Intrinsics.checkNotNullParameter(sharedPreferencesAccessTokenProvider, "sharedPreferencesAccessTokenProvider");
        Intrinsics.checkNotNullParameter(firebaseCrashlytics, "firebaseCrashlytics");
        Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
        Intrinsics.checkNotNullParameter(sharedPreferencesAccessTokenProvider, "sharedPreferencesAccessTokenProvider");
        Intrinsics.checkNotNullParameter("AES/GCM/NoPadding", "transformation");
        Intrinsics.checkNotNullParameter(firebaseCrashlytics, "firebaseCrashlytics");
        this.a = sharedPreferences;
        this.b = sharedPreferencesAccessTokenProvider;
        this.c = firebaseCrashlytics;
        this.d = l.b(new com.quizlet.db.data.models.persisted.types.a(13));
        this.e = l.b(new o(this, 26));
        this.g = sharedPreferences;
        this.h = sharedPreferencesAccessTokenProvider;
    }

    @Override // com.quizlet.data.token.a
    public final String a() throws KeyStoreException {
        String str = this.f;
        if (str != null) {
            return str;
        }
        try {
            if (!g().containsAlias("symmetric_access_token") && g().containsAlias("asymmetric_access_token") && this.h.a() != null) {
                g().deleteEntry("asymmetric_access_token");
                b(null);
            }
            return d();
        } catch (Exception e) {
            c(e);
            return null;
        }
    }

    @Override // com.quizlet.data.token.a
    public final void b(String accessToken) {
        String strEncodeToString;
        this.f = accessToken;
        if (!h()) {
            this.b.b(accessToken);
            return;
        }
        String str = null;
        if (accessToken == null) {
            this.a.edit().putString("encrypted_access_token", null).apply();
            return;
        }
        Intrinsics.checkNotNullParameter(accessToken, "accessToken");
        try {
            synchronized (this) {
                e().init(1, f());
                byte[] iv = e().getIV();
                Intrinsics.checkNotNullExpressionValue(iv, "getIV(...)");
                Intrinsics.checkNotNullParameter(iv, "<this>");
                String strEncodeToString2 = Base64.encodeToString(iv, 3);
                Intrinsics.checkNotNullExpressionValue(strEncodeToString2, "encodeToString(...)");
                this.g.edit().putString("iv", strEncodeToString2).apply();
                Cipher cipherE = e();
                Intrinsics.checkNotNullParameter(accessToken, "<this>");
                byte[] bArrDecode = Base64.decode(accessToken, 3);
                Intrinsics.checkNotNullExpressionValue(bArrDecode, "decode(...)");
                byte[] bArrDoFinal = cipherE.doFinal(bArrDecode);
                Intrinsics.d(bArrDoFinal);
                Intrinsics.checkNotNullParameter(bArrDoFinal, "<this>");
                strEncodeToString = Base64.encodeToString(bArrDoFinal, 3);
                Intrinsics.checkNotNullExpressionValue(strEncodeToString, "encodeToString(...)");
            }
            str = strEncodeToString;
        } catch (Exception e) {
            c(e);
        }
        if (str != null) {
            this.a.edit().putString("encrypted_access_token", str).apply();
        }
    }

    public final void c(Exception exc) {
        com.google.firebase.crashlytics.b bVar = this.c;
        bVar.getClass();
        Map map = Collections.EMPTY_MAP;
        q qVar = bVar.a;
        qVar.o.a.a(new i(qVar, exc));
        SharedPreferences sharedPreferences = this.a;
        sharedPreferences.edit().putBoolean("device_keystore_inconsistent", true).apply();
        sharedPreferences.edit().putString("encrypted_access_token", null).apply();
    }

    public final String d() {
        String strEncodeToString;
        String str = this.f;
        if (str != null) {
            return str;
        }
        String str2 = null;
        if (!g().containsAlias("symmetric_access_token") && !g().containsAlias("asymmetric_access_token")) {
            String strA = this.b.a();
            this.f = strA;
            if (strA != null && h()) {
                this.b.b(null);
                b(this.f);
            }
            return this.f;
        }
        if (!h()) {
            String strA2 = this.b.a();
            this.f = strA2;
            return strA2;
        }
        String value = this.a.getString("encrypted_access_token", null);
        if (value != null) {
            Intrinsics.checkNotNullParameter(value, "value");
            try {
                synchronized (this) {
                    String string = this.g.getString("iv", null);
                    if (string == null) {
                        throw new NullPointerException("IV_PREFS_KEY does not exist");
                    }
                    Intrinsics.checkNotNullParameter(string, "<this>");
                    byte[] bArrDecode = Base64.decode(string, 3);
                    Intrinsics.checkNotNullExpressionValue(bArrDecode, "decode(...)");
                    e().init(2, f(), new GCMParameterSpec(128, bArrDecode));
                    Cipher cipherE = e();
                    Intrinsics.checkNotNullParameter(value, "<this>");
                    byte[] bArrDecode2 = Base64.decode(value, 3);
                    Intrinsics.checkNotNullExpressionValue(bArrDecode2, "decode(...)");
                    byte[] bArrDoFinal = cipherE.doFinal(bArrDecode2);
                    Intrinsics.d(bArrDoFinal);
                    Intrinsics.checkNotNullParameter(bArrDoFinal, "<this>");
                    strEncodeToString = Base64.encodeToString(bArrDoFinal, 3);
                    Intrinsics.checkNotNullExpressionValue(strEncodeToString, "encodeToString(...)");
                }
                str2 = strEncodeToString;
            } catch (Exception e) {
                c(e);
            }
            this.f = str2;
        }
        return this.f;
    }

    public final Cipher e() {
        Object value = this.e.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        return (Cipher) value;
    }

    public final SecretKey f() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        if (g().containsAlias("symmetric_access_token")) {
            try {
                KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) g().getEntry("symmetric_access_token", null);
                if (secretKeyEntry != null) {
                    return secretKeyEntry.getSecretKey();
                }
                return null;
            } catch (Exception e) {
                c(e);
                return null;
            }
        }
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "AndroidKeyStore");
        KeyGenParameterSpec keyGenParameterSpecBuild = new KeyGenParameterSpec.Builder("symmetric_access_token", 3).setBlockModes("GCM").setEncryptionPaddings("NoPadding").setUserAuthenticationRequired(false).build();
        Intrinsics.checkNotNullExpressionValue(keyGenParameterSpecBuild, "build(...)");
        keyGenerator.init(keyGenParameterSpecBuild);
        try {
            return keyGenerator.generateKey();
        } catch (Exception e2) {
            c(e2);
            return null;
        }
    }

    public final KeyStore g() {
        Object value = this.d.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        return (KeyStore) value;
    }

    public final boolean h() {
        try {
            if (!this.a.getBoolean("device_keystore_inconsistent", false)) {
                if (f() != null) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            c(e);
            return false;
        }
    }
}

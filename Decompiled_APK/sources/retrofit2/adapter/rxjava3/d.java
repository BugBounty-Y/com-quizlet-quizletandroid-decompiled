package retrofit2.adapter.rxjava3;

import android.graphics.Typeface;
import android.os.Parcel;
import android.util.Log;
import androidx.camera.camera2.internal.c0;
import androidx.compose.ui.text.font.u;
import androidx.compose.ui.text.font.w;
import androidx.compose.ui.text.font.z;
import androidx.fragment.app.Fragment;
import com.bumptech.glide.load.engine.v;
import com.bumptech.glide.load.f;
import com.bumptech.glide.load.h;
import com.bumptech.glide.load.k;
import com.facebook.internal.C1558m;
import com.facebook.internal.y;
import com.facebook.o;
import com.google.android.gms.appset.zza;
import com.google.android.gms.common.api.internal.i;
import com.google.android.gms.internal.measurement.B3;
import com.google.android.gms.internal.measurement.C3050r3;
import com.google.android.gms.internal.measurement.D3;
import com.google.android.gms.internal.measurement.O2;
import com.google.android.gms.internal.measurement.Q2;
import com.google.android.gms.internal.measurement.S3;
import com.google.android.gms.internal.measurement.W2;
import com.google.android.gms.internal.mlkit_vision_barcode.M6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3771z;
import com.google.android.gms.internal.mlkit_vision_document_scanner.T;
import com.google.android.gms.internal.mlkit_vision_document_scanner.W;
import com.google.android.gms.measurement.internal.AbstractC3893t;
import com.google.android.gms.measurement.internal.r;
import com.google.mlkit.common.sdkinternal.g;
import com.perimeterx.mobile_sdk.doctor_app.ui.q;
import com.quizlet.data.model.C4135i0;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import kotlin.collections.B;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes3.dex */
public final class d implements z, f, k, i, r, com.google.firebase.components.d, com.google.zxing.datamatrix.encoder.b, com.perimeterx.mobile_sdk.doctor_app.state.d, com.quizlet.features.infra.studysetting.data.c, com.quizlet.local.ormlite.util.c {
    public static d b;
    public static d c;
    public final /* synthetic */ int a;

    public /* synthetic */ d(int i) {
        this.a = i;
    }

    public static JSONObject j(String str, JSONObject jSONObject) {
        try {
            if (jSONObject.has(str)) {
                return jSONObject.getJSONObject(str);
            }
            return null;
        } catch (JSONException e) {
            W.a("getObject failed: ", e, "JSONUtils", 6);
            return null;
        }
    }

    public static void k(String str, JSONObject jSONObject, JSONObject jSONObject2) throws JSONException {
        if (jSONObject2.has(str)) {
            try {
                jSONObject.put(str, jSONObject2.optString(str));
            } catch (JSONException e) {
                T.d(e, android.support.v4.media.session.a.y("Error in parsing data. key = ", str, "Error message : "), "JSONUtils", 6);
            }
        }
    }

    public static boolean l(JSONArray jSONArray) {
        return jSONArray == null || jSONArray.length() == 0;
    }

    public static boolean o(JSONObject jSONObject) {
        return jSONObject == null || jSONObject.length() == 0;
    }

    public static Typeface p(String str, u uVar, int i) {
        if (i == 0 && Intrinsics.b(uVar, u.f) && (str == null || str.length() == 0)) {
            return Typeface.DEFAULT;
        }
        return Typeface.create(str == null ? Typeface.DEFAULT : Typeface.create(str, 0), uVar.a, i == 1);
    }

    public static String q(StringBuilder sb) {
        int length = sb.length();
        if (length == 0) {
            throw new IllegalStateException("StringBuilder must not be empty");
        }
        int iCharAt = (sb.charAt(0) << 18) + ((length >= 2 ? sb.charAt(1) : (char) 0) << '\f') + ((length >= 3 ? sb.charAt(2) : (char) 0) << 6) + (length >= 4 ? sb.charAt(3) : (char) 0);
        char c2 = (char) ((iCharAt >> 16) & 255);
        char c3 = (char) ((iCharAt >> 8) & 255);
        char c4 = (char) (iCharAt & 255);
        StringBuilder sb2 = new StringBuilder(3);
        sb2.append(c2);
        if (length >= 2) {
            sb2.append(c3);
        }
        if (length >= 3) {
            sb2.append(c4);
        }
        return sb2.toString();
    }

    public static C4135i0 s(DBUser local) {
        Intrinsics.checkNotNullParameter(local, "local");
        long id = local.getId();
        String username = local.getUsername();
        if (username == null) {
            username = "";
        }
        long timestamp = local.getTimestamp();
        long lastModified = local.getLastModified();
        int userUpgradeType = local.getUserUpgradeType();
        boolean isVerified = local.getIsVerified();
        boolean isAdmin = local.getIsAdmin();
        boolean isLocked = local.getIsLocked();
        String imageUrl = local.getImageUrl();
        if (imageUrl == null) {
            imageUrl = "";
        }
        String timeZone = local.getTimeZone();
        String str = username;
        long birthYear = local.getBirthYear();
        long birthMonth = local.getBirthMonth();
        long birthDay = local.getBirthDay();
        boolean isConfirmed = local.getIsConfirmed();
        int selfIdentifiedUserType = local.getSelfIdentifiedUserType();
        String profileImageId = local.getProfileImageId();
        String email = local.getEmail();
        boolean zHasPassword = local.hasPassword();
        boolean zHasFacebook = local.hasFacebook();
        boolean zHasGoogle = local.hasGoogle();
        boolean zIsConfirmationRequired = local.isConfirmationRequired();
        boolean zCanChangeUsername = local.canChangeUsername();
        boolean isUnderAge = local.getIsUnderAge();
        boolean isUnderAgeForAds = local.getIsUnderAgeForAds();
        boolean zNeedsChildDirectedTreatment = local.needsChildDirectedTreatment();
        String mobileLocale = local.getMobileLocale();
        String userLocalePreference = local.getUserLocalePreference();
        long srsNotificationTimeSec = local.getSrsNotificationTimeSec();
        boolean srsPushNotificationsEnabled = local.getSrsPushNotificationsEnabled();
        boolean isEligibleForFreeTrial = local.getIsEligibleForFreeTrial();
        boolean hasOptedIntoFreeOfflinePromo = local.getHasOptedIntoFreeOfflinePromo();
        boolean isSelfLearner = local.getIsSelfLearner();
        String signupCountryCode = local.getSignupCountryCode();
        if (signupCountryCode == null) {
            signupCountryCode = "";
        }
        String countryCode = local.getCountryCode();
        if (countryCode == null) {
            countryCode = "";
        }
        return new C4135i0(id, str, timestamp, lastModified, userUpgradeType, isVerified, isAdmin, isLocked, imageUrl, timeZone, birthYear, birthMonth, birthDay, isConfirmed, selfIdentifiedUserType, profileImageId, email, zHasPassword, zHasFacebook, zHasGoogle, zIsConfirmationRequired, zCanChangeUsername, isUnderAge, isUnderAgeForAds, zNeedsChildDirectedTreatment, mobileLocale, userLocalePreference, srsNotificationTimeSec, srsPushNotificationsEnabled, isEligibleForFreeTrial, hasOptedIntoFreeOfflinePromo, isSelfLearner, signupCountryCode, countryCode);
    }

    public static DBUser t(C4135i0 data) {
        Intrinsics.checkNotNullParameter(data, "data");
        DBUser dBUser = new DBUser();
        dBUser.setId(data.a);
        dBUser.setUsername(data.b);
        dBUser.setTimestamp((int) data.c);
        dBUser.setLastModified(data.d);
        dBUser.setUserUpgradeType(data.e);
        dBUser.setIsVerified(data.f);
        dBUser.setIsAdmin(data.g);
        dBUser.setIsLocked(data.h);
        dBUser.setImageUrl(data.i);
        dBUser.setTimeZone(data.j);
        dBUser.setBirthYear((int) data.k);
        dBUser.setBirthMonth((int) data.l);
        dBUser.setBirthDay((int) data.m);
        dBUser.setIsConfirmed(data.n);
        dBUser.setSelfIdentifiedUserType(data.o);
        dBUser.setProfileImageId(data.p);
        dBUser.setEmail(data.q);
        dBUser.setHasPassword(data.r);
        dBUser.setHasFacebook(data.s);
        dBUser.setHasGoogle(data.t);
        dBUser.setCanChangeUsername(data.v);
        dBUser.setIsConfirmationRequired(data.u);
        dBUser.setIsUnderAge(data.w);
        dBUser.setIsUnderAgeForAds(data.x);
        dBUser.setNeedsChildDirectedTreatment(data.y);
        dBUser.setMobileLocale(data.z);
        dBUser.setUserLocalePreference(data.A);
        dBUser.setSrsNotificationTimeSec((int) data.B);
        dBUser.setSrsPushNotificationsEnabled(data.C);
        dBUser.setIsEligibleForFreeTrial(data.D);
        dBUser.setHasOptedIntoFreeOfflinePromo(data.E);
        dBUser.setIsSelfLearner(data.F);
        dBUser.setSignupCountryCode(data.G);
        dBUser.setCountryCode(data.H);
        return dBUser;
    }

    @Override // com.perimeterx.mobile_sdk.doctor_app.state.d
    public com.perimeterx.mobile_sdk.doctor_app.state.a a() {
        return null;
    }

    @Override // com.google.android.gms.common.api.internal.i
    public void accept(Object obj, Object obj2) {
        com.google.android.gms.internal.appset.c cVar = (com.google.android.gms.internal.appset.c) ((com.google.android.gms.internal.appset.b) obj).m();
        zza zzaVar = new zza(null, null);
        com.google.android.gms.fido.fido2.b bVar = new com.google.android.gms.fido.fido2.b((com.google.android.gms.tasks.f) obj2, 1);
        Parcel parcelObtain = Parcel.obtain();
        parcelObtain.writeInterfaceToken("com.google.android.gms.appset.internal.IAppSetService");
        int i = com.google.android.gms.internal.appset.a.a;
        parcelObtain.writeInt(1);
        zzaVar.writeToParcel(parcelObtain, 0);
        parcelObtain.writeStrongBinder(bVar);
        Parcel parcelObtain2 = Parcel.obtain();
        try {
            cVar.a.transact(1, parcelObtain, parcelObtain2, 0);
            parcelObtain2.readException();
        } finally {
            parcelObtain.recycle();
            parcelObtain2.recycle();
        }
    }

    @Override // com.perimeterx.mobile_sdk.doctor_app.state.d
    public com.perimeterx.mobile_sdk.doctor_app.state.a b() {
        return null;
    }

    @Override // com.perimeterx.mobile_sdk.doctor_app.state.d
    public Fragment c() {
        return new q();
    }

    @Override // com.perimeterx.mobile_sdk.doctor_app.state.d
    public ArrayList d() {
        return B.f(com.perimeterx.mobile_sdk.doctor_app.state.e.a);
    }

    @Override // androidx.compose.ui.text.font.z
    public Typeface e(u uVar, int i) {
        return p(null, uVar, i);
    }

    @Override // com.google.firebase.components.d
    public Object f(c0 c0Var) {
        return new com.google.mlkit.common.sdkinternal.d(c0Var.b(g.class));
    }

    @Override // com.quizlet.local.ormlite.util.c
    public ArrayList g(List list) {
        return AbstractC3771z.c(this, list);
    }

    @Override // com.quizlet.local.ormlite.util.c
    public /* bridge */ /* synthetic */ Object h(Object obj) {
        return s((DBUser) obj);
    }

    @Override // com.quizlet.features.infra.studysetting.data.c
    public QuestionSettings i(QuestionSettings settings, com.quizlet.features.infra.studysetting.managers.a settingManager) {
        Intrinsics.checkNotNullParameter(settings, "settings");
        Intrinsics.checkNotNullParameter(settingManager, "settingManager");
        return QuestionSettings.a(QuestionSettings.a(settings, null, null, false, false, false, true, false, false, false, null, null, false, false, false, false, false, 255879), M6.c(false, false, true), M6.c(settings.c(), true ^ settings.c(), false), false, false, false, false, false, false, false, null, null, false, false, false, false, false, 262140);
    }

    @Override // com.bumptech.glide.load.b
    public boolean m(Object obj, File file, h hVar) throws Throwable {
        try {
            com.bumptech.glide.util.b.d(((com.bumptech.glide.load.resource.gif.g) ((com.bumptech.glide.load.resource.gif.b) ((v) obj).get()).a.b).a.d.asReadOnlyBuffer(), file);
            return true;
        } catch (IOException e) {
            if (!Log.isLoggable("GifEncoder", 5)) {
                return false;
            }
            Log.w("GifEncoder", "Failed to encode GIF drawable data", e);
            return false;
        }
    }

    @Override // com.bumptech.glide.load.k
    public int n(h hVar) {
        return 1;
    }

    public synchronized C1558m r() {
        com.facebook.internal.v vVarB = y.b(o.b());
        if (vVarB == null) {
            return C1558m.d.l();
        }
        return vVarB.e;
    }

    @Override // com.google.android.gms.measurement.internal.r
    public Object zza() {
        switch (this.a) {
            case 10:
                List list = AbstractC3893t.a;
                Boolean bool = (Boolean) S3.a.b();
                bool.getClass();
                return bool;
            case 11:
                List list2 = AbstractC3893t.a;
                O2.b.get();
                return Integer.valueOf((int) ((Long) Q2.k0.b()).longValue());
            case 12:
                Boolean bool2 = (Boolean) C3050r3.a.b();
                bool2.getClass();
                return bool2;
            case 13:
                List list3 = AbstractC3893t.a;
                O2.b.get();
                return Integer.valueOf((int) ((Long) Q2.H.b()).longValue());
            case 14:
                List list4 = AbstractC3893t.a;
                O2.b.get();
                Long l = (Long) Q2.D.b();
                l.getClass();
                return l;
            case 15:
                List list5 = AbstractC3893t.a;
                B3.b.get();
                Long l2 = (Long) D3.e.b();
                l2.getClass();
                return l2;
            case 16:
                List list6 = AbstractC3893t.a;
                O2.b.get();
                return (String) Q2.X.b();
            default:
                List list7 = AbstractC3893t.a;
                Boolean bool3 = (Boolean) W2.b.b();
                bool3.getClass();
                return bool3;
        }
    }

    @Override // com.bumptech.glide.load.f
    public void a(byte[] bArr, Object obj, MessageDigest messageDigest) {
    }

    @Override // androidx.compose.ui.text.font.z
    public Typeface b(w wVar, u uVar, int i) {
        wVar.getClass();
        return p("sans-serif", uVar, i);
    }

    /* JADX WARN: Code restructure failed: missing block: B:20:0x0051, code lost:
    
        com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3723t.b(r1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:21:0x0054, code lost:
    
        throw null;
     */
    @Override // com.google.zxing.datamatrix.encoder.b
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void c(com.google.zxing.datamatrix.encoder.c r12) {
        /*
            Method dump skipped, instructions count: 236
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: retrofit2.adapter.rxjava3.d.c(com.google.zxing.datamatrix.encoder.c):void");
    }

    @Override // com.quizlet.features.infra.studysetting.data.c
    public QuestionSettings d(QuestionSettings settings, com.quizlet.features.infra.studysetting.managers.a settingManager) {
        Intrinsics.checkNotNullParameter(settings, "settings");
        Intrinsics.checkNotNullParameter(settingManager, "settingManager");
        return QuestionSettings.a(settingManager.c(), null, null, settings.c, false, false, false, false, settings.h, settings.i, null, null, false, false, false, false, false, 261755);
    }
}

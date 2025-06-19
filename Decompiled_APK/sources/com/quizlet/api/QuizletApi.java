package com.quizlet.api;

import com.amazon.device.ads.DTBMetricsConfiguration;
import com.quizlet.api.model.AddPasswordRequest;
import com.quizlet.api.model.ApiThreeWrapper;
import com.quizlet.api.model.ChangeEmailRequest;
import com.quizlet.api.model.ChangePasswordRequest;
import com.quizlet.api.model.ChangeUsernameRequest;
import com.quizlet.api.model.CompatibilityCheckDataWrapper;
import com.quizlet.api.model.CountryInfoDataWrapper;
import com.quizlet.api.model.DataWrapper;
import com.quizlet.api.model.ImageAnalysisResponse;
import com.quizlet.api.model.JoinClassRequest;
import com.quizlet.api.model.LanguageSuggestionDataWrapper;
import com.quizlet.api.model.LanguageSuggestionRequest;
import com.quizlet.api.model.ReauthenticationRequest;
import com.quizlet.api.model.SubscriptionRequest;
import com.quizlet.api.model.SuggestionsDataWrapper;
import io.reactivex.rxjava3.core.p;
import java.util.Map;
import kotlin.Metadata;
import okhttp3.F;
import okhttp3.J;
import org.jetbrains.annotations.NotNull;
import retrofit2.K;
import retrofit2.http.o;
import retrofit2.http.s;
import retrofit2.http.t;

@Metadata
/* loaded from: classes2.dex */
public interface QuizletApi {

    @Metadata
    public static final class DefaultImpls {
    }

    @Metadata
    public static final class Endpoints {
    }

    @o("logs")
    @NotNull
    p<K<J>> A(@NotNull @retrofit2.http.a F f);

    @o("forgot/username")
    @NotNull
    p<K<ApiThreeWrapper<DataWrapper>>> B(@NotNull @retrofit2.http.a Map<String, String> map);

    @o("entered-set-passwords/save")
    @NotNull
    p<K<ApiThreeWrapper<DataWrapper>>> C(@NotNull @retrofit2.http.a F f);

    @o("google-sign-in-login")
    @NotNull
    p<K<ApiThreeWrapper<DataWrapper>>> a(@NotNull @retrofit2.http.a Map<String, String> map);

    @retrofit2.http.f("resolve-url")
    @NotNull
    p<K<ApiThreeWrapper<DataWrapper>>> b(@t(DTBMetricsConfiguration.APSMETRICS_URL) @NotNull String str);

    @o("users/reauthenticate-google-sign-in")
    @NotNull
    p<K<ApiThreeWrapper<DataWrapper>>> c(@NotNull @retrofit2.http.a ReauthenticationRequest reauthenticationRequest);

    @retrofit2.http.f("classes")
    @NotNull
    p<K<ApiThreeWrapper<DataWrapper>>> d(@t("filters[code]") @NotNull String str);

    @o("logout")
    @NotNull
    p<K<J>> e();

    @o("users/change-email")
    @NotNull
    p<K<ApiThreeWrapper<DataWrapper>>> f(@NotNull @retrofit2.http.a ChangeEmailRequest changeEmailRequest);

    @o("direct-login")
    @NotNull
    p<K<ApiThreeWrapper<DataWrapper>>> g(@NotNull @retrofit2.http.a Map<String, String> map);

    @o("users/google-subscription/save?include[subscription]=user")
    @NotNull
    p<K<ApiThreeWrapper<DataWrapper>>> h(@NotNull @retrofit2.http.a SubscriptionRequest subscriptionRequest);

    @retrofit2.http.f("country-information")
    @NotNull
    p<K<ApiThreeWrapper<CountryInfoDataWrapper>>> i();

    @o("direct-signup")
    @NotNull
    p<K<ApiThreeWrapper<DataWrapper>>> j(@NotNull @retrofit2.http.a Map<String, String> map);

    @o("users/reauthenticate")
    @NotNull
    p<K<ApiThreeWrapper<DataWrapper>>> k(@NotNull @retrofit2.http.a ReauthenticationRequest reauthenticationRequest);

    @o("users/change-username")
    @NotNull
    p<K<ApiThreeWrapper<DataWrapper>>> l(@NotNull @retrofit2.http.a ChangeUsernameRequest changeUsernameRequest);

    @o("users/add-password")
    @NotNull
    p<K<ApiThreeWrapper<DataWrapper>>> m(@NotNull @retrofit2.http.a AddPasswordRequest addPasswordRequest);

    @o("sets/{setId}/copy")
    @NotNull
    p<K<ApiThreeWrapper<DataWrapper>>> n(@s("setId") long j);

    @o("users/change-password")
    @NotNull
    p<K<ApiThreeWrapper<DataWrapper>>> o(@NotNull @retrofit2.http.a ChangePasswordRequest changePasswordRequest);

    @retrofit2.http.f("suggestions/definition")
    @NotNull
    p<K<ApiThreeWrapper<SuggestionsDataWrapper>>> p(@t("word") String str, @t("prefix") @NotNull String str2, @t("localTermId") Long l, @t("userId") Long l2, @t("wordLang") String str3, @t("defLang") String str4, @t("setTitle") String str5, @t("limit") Integer num, @t("corroboration") Integer num2);

    @o("oauth-extra-info")
    @NotNull
    p<K<ApiThreeWrapper<DataWrapper>>> q(@NotNull @retrofit2.http.a Map<String, String> map);

    @o("users/profile-image")
    @NotNull
    p<K<ApiThreeWrapper<DataWrapper>>> r(@NotNull @retrofit2.http.a F f);

    @o("forgot/password")
    @NotNull
    p<K<ApiThreeWrapper<DataWrapper>>> s(@NotNull @retrofit2.http.a Map<String, String> map);

    @o("class-memberships/save")
    @NotNull
    p<K<ApiThreeWrapper<DataWrapper>>> t(@NotNull @retrofit2.http.a JoinClassRequest joinClassRequest);

    @o("image-analysis?skipFullTextAnnotation=true")
    @NotNull
    p<K<ImageAnalysisResponse>> u(@NotNull @retrofit2.http.a F f);

    @retrofit2.http.f("profile-images")
    @NotNull
    p<K<ApiThreeWrapper<DataWrapper>>> v();

    @retrofit2.http.f("compatibility-check")
    @NotNull
    p<K<ApiThreeWrapper<CompatibilityCheckDataWrapper>>> w(@t("platform") @NotNull String str, @t("platformVersion") @NotNull String str2, @t("buildNumber") Integer num, @t("versionNumber") @NotNull String str3);

    @retrofit2.http.f("sessions/highscores")
    @NotNull
    p<K<ApiThreeWrapper<DataWrapper>>> x(@t(encoded = false, value = "filters[itemId]") long j, @t(encoded = false, value = "filters[itemType]") int i, @t(encoded = false, value = "filters[type]") int i2, @t(encoded = false, value = "include[session]") @NotNull String str);

    @o("suggestions/language")
    @NotNull
    p<K<ApiThreeWrapper<LanguageSuggestionDataWrapper>>> y(@NotNull @retrofit2.http.a LanguageSuggestionRequest languageSuggestionRequest);

    @retrofit2.http.f("suggestions/word")
    @NotNull
    p<K<ApiThreeWrapper<SuggestionsDataWrapper>>> z(@t("prefix") String str, @t("localTermId") Long l, @t("userId") Long l2, @t("wordLang") String str2, @t("defLang") String str3, @t("setTitle") String str4, @t("limit") Integer num, @t("corroboration") Integer num2);
}

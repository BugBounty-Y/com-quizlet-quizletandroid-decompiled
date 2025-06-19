package com.quizlet.api.util;

import android.content.Context;
import com.quizlet.api.model.ServerProvidedError;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class ApiErrorResolver {

    @NotNull
    private static final String API_ERROR_400_EMPTY_SET_TITLE = "requires_title";

    @NotNull
    private static final String API_ERROR_400_INSECURE_PASSWORD = "insecure_password";

    @NotNull
    private static final String API_ERROR_400_INVALID_BIRTH_YEAR = "invalid_birth_year";

    @NotNull
    private static final String API_ERROR_400_INVALID_EMAIL = "invalid_email";

    @NotNull
    private static final String API_ERROR_400_INVALID_EMAIL_DOMAIN = "invalid_email_domain";

    @NotNull
    private static final String API_ERROR_400_LOGIN_MISSING_PASSWORD = "login_missing_password";

    @NotNull
    private static final String API_ERROR_400_LOGIN_MISSING_USERNAME = "login_missing_username";

    @NotNull
    private static final String API_ERROR_400_MIN_TERMS = "min_terms";

    @NotNull
    private static final String API_ERROR_400_PASSWORD_MISMATCH = "password_mismatch";

    @NotNull
    private static final String API_ERROR_400_PASSWORD_NO_CHANGE = "password_no_change";

    @NotNull
    private static final String API_ERROR_400_PASSWORD_TOO_SHORT = "password_too_short";

    @NotNull
    private static final String API_ERROR_400_REQUIRES_PASSWORD = "requires_password";

    @NotNull
    private static final String API_ERROR_400_SET_INCORRECT_PASSWORD = "incorrect_password";

    @NotNull
    private static final String API_ERROR_400_UNDERAGE_NO_EMAIL_CHANGE = "exception_cannot_update_email_underage";

    @NotNull
    private static final String API_ERROR_400_USERNAME_AS_PASSWORD = "username_as_password";

    @NotNull
    private static final String API_ERROR_400_USERNAME_CHANGE_MORE_THAN_ONCE = "exception_cannot_change_username_more_than_once";

    @NotNull
    private static final String API_ERROR_400_USERNAME_CONTAINED_RESERVED_WORD = "username_contained_reserved_word";

    @NotNull
    private static final String API_ERROR_400_USERNAME_INVALID_CHARS = "username_invalid_chars";

    @NotNull
    private static final String API_ERROR_400_USERNAME_IS_TAKEN = "username_is_taken";

    @NotNull
    private static final String API_ERROR_400_USERNAME_MUST_START_WITH_LETTER = "username_must_start_with_letter";

    @NotNull
    private static final String API_ERROR_400_USERNAME_PROFANITY = "username_profanity";

    @NotNull
    private static final String API_ERROR_400_USERNAME_RESERVED_WORD = "username_reserved_word";

    @NotNull
    private static final String API_ERROR_400_USERNAME_TOO_LONG = "username_too_long";

    @NotNull
    private static final String API_ERROR_400_USERNAME_TOO_SHORT = "username_too_short";

    @NotNull
    private static final String API_ERROR_401_EXCEPTION_INVALID_ACCESS = "exception_invalid_access";

    @NotNull
    private static final String API_ERROR_401_INVALID_GRANT = "invalid_grant";

    @NotNull
    private static final String API_ERROR_401_LOGIN_FACEBOOK_ONLY = "login_facebook_only";

    @NotNull
    private static final String API_ERROR_401_LOGIN_GOOGLE_ONLY = "login_google_only";

    @NotNull
    private static final String API_ERROR_401_LOGIN_UNAUTHORIZED_ACCOUNT = "login_unauthorized_account";

    @NotNull
    private static final String API_ERROR_401_SIGNUP_EMAIL_IN_USE = "direct_signup_email_in_use";

    @NotNull
    private static final String API_ERROR_403_ACCOUNT_PASSWORD_ALREADY_EXISTS = "exception_account_password_already_exists";

    @NotNull
    private static final String API_ERROR_404_EXCEPTION_NOT_FOUND = "exception_not_found";
    public static final ApiErrorResolver a = new ApiErrorResolver();

    public static final String a(Context context, ServerProvidedError error) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(error, "error");
        String identifier = error.getIdentifier();
        String serverMessage = error.getServerMessage();
        Integer numB = b(identifier);
        return numB == null ? serverMessage : context.getString(numB.intValue());
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Code restructure failed: missing block: B:116:0x0190, code lost:
    
        if (r3.equals(com.quizlet.api.util.ApiErrorResolver.API_ERROR_400_INVALID_EMAIL) == false) goto L155;
     */
    /* JADX WARN: Code restructure failed: missing block: B:119:0x019b, code lost:
    
        return java.lang.Integer.valueOf(com.quizlet.quizletandroid.R.string.api_error_invalid_email);
     */
    /* JADX WARN: Code restructure failed: missing block: B:12:0x0026, code lost:
    
        if (r3.equals(com.quizlet.api.util.ApiErrorResolver.API_ERROR_400_USERNAME_CONTAINED_RESERVED_WORD) == false) goto L155;
     */
    /* JADX WARN: Code restructure failed: missing block: B:20:0x0042, code lost:
    
        if (r3.equals(com.quizlet.api.util.ApiErrorResolver.API_ERROR_400_USERNAME_RESERVED_WORD) == false) goto L155;
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x005b, code lost:
    
        if (r3.equals(com.quizlet.api.util.ApiErrorResolver.API_ERROR_400_USERNAME_MUST_START_WITH_LETTER) == false) goto L155;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x0077, code lost:
    
        if (r3.equals(com.quizlet.api.util.ApiErrorResolver.API_ERROR_400_USERNAME_AS_PASSWORD) == false) goto L155;
     */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x0093, code lost:
    
        if (r3.equals(com.quizlet.api.util.ApiErrorResolver.API_ERROR_400_INVALID_EMAIL_DOMAIN) == false) goto L155;
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x009d, code lost:
    
        if (r3.equals(com.quizlet.api.util.ApiErrorResolver.API_ERROR_400_USERNAME_INVALID_CHARS) == false) goto L155;
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x00a7, code lost:
    
        if (r3.equals(com.quizlet.api.util.ApiErrorResolver.API_ERROR_400_INSECURE_PASSWORD) == false) goto L155;
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x00b2, code lost:
    
        return java.lang.Integer.valueOf(com.quizlet.quizletandroid.R.string.api_error_insecure_password);
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x00b9, code lost:
    
        if (r3.equals(com.quizlet.api.util.ApiErrorResolver.API_ERROR_400_USERNAME_TOO_LONG) == false) goto L155;
     */
    /* JADX WARN: Code restructure failed: missing block: B:73:0x00f9, code lost:
    
        if (r3.equals(com.quizlet.api.util.ApiErrorResolver.API_ERROR_400_USERNAME_TOO_SHORT) == false) goto L155;
     */
    /* JADX WARN: Code restructure failed: missing block: B:86:0x0127, code lost:
    
        if (r3.equals(com.quizlet.api.util.ApiErrorResolver.API_ERROR_400_USERNAME_PROFANITY) == false) goto L155;
     */
    /* JADX WARN: Code restructure failed: missing block: B:89:0x0132, code lost:
    
        return java.lang.Integer.valueOf(com.quizlet.quizletandroid.R.string.api_error_invalid_username);
     */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue
    java.lang.NullPointerException: Cannot invoke "java.util.List.iterator()" because the return value of "jadx.core.dex.visitors.regions.SwitchOverStringVisitor$SwitchData.getNewCases()" is null
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.restoreSwitchOverString(SwitchOverStringVisitor.java:109)
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.visitRegion(SwitchOverStringVisitor.java:66)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:77)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:82)
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.Integer b(java.lang.String r3) {
        /*
            Method dump skipped, instructions count: 684
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.api.util.ApiErrorResolver.b(java.lang.String):java.lang.Integer");
    }
}

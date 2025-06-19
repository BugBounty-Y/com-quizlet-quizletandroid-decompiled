package com.onetrust.otpublishers.headless.Public.Response;

/* loaded from: classes2.dex */
public final class OTResponseCode {
    public static final int CORRUPTED_DATA_RESPONSE = 7;
    public static final int EMPTY_NETWORK_RESPONSE = 2;
    public static final int EMPTY_PARAMETER_PASSED = 4;
    public static final int FAILED = -1;
    public static final int INVALID_LANGUAGE_CODE = 5;
    public static final int MULTI_PROFILE_DATA_PARSED_WITH_EXISTING_DATA = 9;
    public static final int MULTI_PROFILE_MAXIMUM_LIMIT_REACHED = 8;
    public static final int MULTI_PROFILE_PROFILE_ALREADY_ACTIVE = 10;
    public static final int MULTI_PROFILE_PROFILE_DELETED_SUCCESSFULLY = 14;
    public static final int MULTI_PROFILE_PROFILE_DELETE_FAILED = 13;
    public static final int MULTI_PROFILE_PROFILE_RENAMED_SUCCESSFULLY = 16;
    public static final int MULTI_PROFILE_PROFILE_RENAME_FAILED = 15;
    public static final int MULTI_PROFILE_SDK_NOT_INITIALIZED = 11;
    public static final int MULTI_PROFILE_SWITCH_PROFILE_NOT_ALLOWED = 12;
    public static final int NETWORK_CALL_FAILURE = 3;
    public static final int NETWORK_NOT_AVAILABLE = 6;
    public static final int NOT_INITIALIZED = -2;
    public static final int OT_RESPONSE_CODE_101 = 101;
    public static final int OT_RESPONSE_CODE_103 = 103;
    public static final int OT_RESPONSE_CODE_104 = 104;
    public static final int OT_RESPONSE_CODE_IAB_NETWORK_CALL_FAILURE = 102;
    public static final int SUCCESS = 1;
    public static final int UNKNOWN_ERROR = -3;

    private OTResponseCode() {
        throw new IllegalStateException("Utility class");
    }
}

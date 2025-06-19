package com.pubmatic.sdk.webrendering.mraid;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.MediaStore;
import android.telephony.TelephonyManager;
import androidx.annotation.NonNull;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.pubmatic.sdk.common.log.POBLog;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.pubmatic.sdk.webrendering.mraid.c, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public class C4074c {
    private static final String[] a = {"yyyy-MM-dd'T'HH:mm:ssZZZZZ", "yyyy-MM-dd'T'HH:mmZZZZZ", "yyyy-MM-dd'T'HH:mmZ", "yyyy-MM-dd'T'HH:mmXXX"};

    public static boolean a(@NonNull Context context, @NonNull Bitmap bitmap, @NonNull String str) throws Throwable {
        Uri uriFromFile;
        OutputStream outputStreamOpenOutputStream = null;
        try {
            try {
                if (Build.VERSION.SDK_INT >= 29) {
                    ContentValues contentValues = new ContentValues();
                    contentValues.put("title", str);
                    contentValues.put("_display_name", str);
                    contentValues.put("mime_type", "image/jpeg");
                    contentValues.put("date_added", Long.valueOf(System.currentTimeMillis() / 1000));
                    contentValues.put("relative_path", Environment.DIRECTORY_PICTURES);
                    ContentResolver contentResolver = context.getContentResolver();
                    uriFromFile = contentResolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, contentValues);
                    if (uriFromFile != null) {
                        outputStreamOpenOutputStream = contentResolver.openOutputStream(uriFromFile);
                    }
                } else {
                    File file = new File(String.valueOf(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES)), str);
                    FileOutputStream fileOutputStream = new FileOutputStream(file);
                    try {
                        uriFromFile = Uri.fromFile(file);
                        outputStreamOpenOutputStream = fileOutputStream;
                    } catch (Exception e) {
                        e = e;
                        outputStreamOpenOutputStream = fileOutputStream;
                        POBLog.debug("POBMRAIDUtil", "Not able to store image : " + e.getLocalizedMessage(), new Object[0]);
                        if (outputStreamOpenOutputStream != null) {
                            try {
                                outputStreamOpenOutputStream.flush();
                                outputStreamOpenOutputStream.close();
                            } catch (IOException unused) {
                                POBLog.debug("POBMRAIDUtil", "Unable to close the outputStream.", new Object[0]);
                            }
                        }
                        return false;
                    } catch (Throwable th) {
                        th = th;
                        outputStreamOpenOutputStream = fileOutputStream;
                        if (outputStreamOpenOutputStream != null) {
                            try {
                                outputStreamOpenOutputStream.flush();
                                outputStreamOpenOutputStream.close();
                            } catch (IOException unused2) {
                                POBLog.debug("POBMRAIDUtil", "Unable to close the outputStream.", new Object[0]);
                            }
                        }
                        throw th;
                    }
                }
            } catch (Exception e2) {
                e = e2;
            }
            if (outputStreamOpenOutputStream == null) {
                POBLog.debug("POBMRAIDUtil", "Not able to store image.", new Object[0]);
                if (outputStreamOpenOutputStream != null) {
                    try {
                        outputStreamOpenOutputStream.flush();
                        outputStreamOpenOutputStream.close();
                    } catch (IOException unused3) {
                        POBLog.debug("POBMRAIDUtil", "Unable to close the outputStream.", new Object[0]);
                    }
                }
                return false;
            }
            bitmap.compress(Bitmap.CompressFormat.JPEG, 100, outputStreamOpenOutputStream);
            outputStreamOpenOutputStream.flush();
            outputStreamOpenOutputStream.close();
            POBLog.debug("POBMRAIDUtil", "Image stored at :" + uriFromFile, new Object[0]);
            Intent intent = new Intent("android.intent.action.MEDIA_SCANNER_SCAN_FILE");
            intent.setData(uriFromFile);
            context.sendBroadcast(intent);
            try {
                outputStreamOpenOutputStream.flush();
                outputStreamOpenOutputStream.close();
                return true;
            } catch (IOException unused4) {
                POBLog.debug("POBMRAIDUtil", "Unable to close the outputStream.", new Object[0]);
                return true;
            }
        } catch (Throwable th2) {
            th = th2;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x005e  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x0065  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x00d5 A[Catch: JSONException -> 0x00ea, TryCatch #0 {JSONException -> 0x00ea, blocks: (B:3:0x000f, B:5:0x0015, B:7:0x0020, B:9:0x002a, B:30:0x0069, B:32:0x0070, B:33:0x0079, B:35:0x007f, B:37:0x0089, B:38:0x0095, B:39:0x009a, B:40:0x009b, B:41:0x00a0, B:42:0x00a1, B:44:0x00a8, B:45:0x00b1, B:47:0x00b7, B:49:0x00c1, B:50:0x00cd, B:51:0x00d4, B:52:0x00d5, B:54:0x00dc, B:16:0x0040, B:19:0x004a, B:22:0x0054), top: B:59:0x000f }] */
    @androidx.annotation.NonNull
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static java.lang.String b(@androidx.annotation.NonNull org.json.JSONObject r11) throws org.json.JSONException, java.lang.IllegalArgumentException {
        /*
            Method dump skipped, instructions count: 240
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.pubmatic.sdk.webrendering.mraid.C4074c.b(org.json.JSONObject):java.lang.String");
    }

    @NonNull
    public static JSONObject getHeightWidthJson(int i, int i2) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        try {
            jSONObject.put(OTUXParamsKeys.OT_UX_WIDTH, i);
            jSONObject.put(OTUXParamsKeys.OT_UX_HEIGHT, i2);
            return jSONObject;
        } catch (JSONException unused) {
            POBLog.error("POBMRAIDUtil", android.support.v4.media.session.a.j("JSON Exception, Not able to generate JSON for given width :", i, " and height ", " !", i2), new Object[0]);
            return jSONObject;
        }
    }

    @NonNull
    public static String getMRAIDEnvironment(String str, String str2, Boolean bool, Boolean bool2) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        try {
            jSONObject.put("version", "3.0");
            jSONObject.put("sdk", "PubMatic_OpenWrap_SDK");
            jSONObject.put("sdkVersion", "3.7.0");
            if (str != null) {
                jSONObject.put("appId", str);
            }
            if (str2 != null) {
                jSONObject.put("ifa", str2);
            }
            if (bool != null) {
                jSONObject.put("limitAdTracking", bool);
            }
            if (bool2 != null) {
                jSONObject.put("coppa", bool2);
            }
        } catch (JSONException unused) {
            POBLog.error("POBMRAIDUtil", "JSON Exception, not able to generate MRAID environment.", new Object[0]);
        }
        return "<script> window.MRAID_ENV = " + jSONObject + "</script>";
    }

    @NonNull
    public static JSONObject getRectJson(int i, int i2, int i3, int i4) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        try {
            jSONObject.put(OTUXParamsKeys.OT_UX_WIDTH, i3);
            jSONObject.put(OTUXParamsKeys.OT_UX_HEIGHT, i4);
            jSONObject.put("x", i);
            jSONObject.put("y", i2);
            return jSONObject;
        } catch (JSONException unused) {
            StringBuilder sbW = android.support.v4.media.session.a.w("JSON Exception, Not able to generate JSON for x:", i, " ,y:", " ,width:", i2);
            sbW.append(i3);
            sbW.append(" ,height:");
            sbW.append(i4);
            sbW.append(" !");
            POBLog.error("POBMRAIDUtil", sbW.toString(), new Object[0]);
            return jSONObject;
        }
    }

    @NonNull
    public static h getResizeValues(int i, int i2, int i3, int i4, boolean z, @NonNull h hVar, int i5, int i6) {
        int i7;
        int screenWidth = com.pubmatic.sdk.common.utility.o.getScreenWidth();
        int screenHeight = com.pubmatic.sdk.common.utility.o.getScreenHeight();
        int i8 = hVar.getxPosition() + i;
        int i9 = hVar.getyPosition() + i2;
        int i10 = 0;
        if (i3 >= screenWidth && i4 >= screenHeight) {
            return new h(false, "Size must be smaller than the max size.");
        }
        if (i3 < 50 || i4 < 50) {
            return new h(false, "Size must be greater than the 50x50 size.");
        }
        if (z) {
            int i11 = i8 + i3;
            if (i11 < i5 || i11 > screenWidth || i9 < 0 || i9 > screenHeight - i6) {
                return new h(false, "Not able to show Close Button! No Space for close Button.");
            }
        } else {
            if (i3 > screenWidth) {
                i3 = screenWidth;
            }
            if (i4 > screenHeight) {
                i4 = screenHeight;
            }
            if (i8 < 0) {
                i7 = 0;
            } else {
                if (i8 + i3 > screenWidth) {
                    i7 = (int) (i8 - (r14 - screenWidth));
                } else {
                    i7 = i8;
                }
            }
            if (i9 >= 0) {
                if (i9 + i4 > screenHeight) {
                    i10 = (int) (i9 - (r11 - screenHeight));
                } else {
                    i10 = i9;
                }
            }
            i8 = (int) (i8 - (i8 - i7));
            i9 = (int) (i9 - (i9 - i10));
        }
        return new h(com.pubmatic.sdk.common.utility.o.convertDpToPixel(i8), com.pubmatic.sdk.common.utility.o.convertDpToPixel(i9), com.pubmatic.sdk.common.utility.o.convertDpToPixel(i4), com.pubmatic.sdk.common.utility.o.convertDpToPixel(i3), true, "Ok");
    }

    private static String b(@NonNull JSONArray jSONArray) {
        if (jSONArray.length() == 0) {
            POBLog.error("POBMRAIDUtil", "Must have at least 1 day of the week if specifying repeating weekly.", new Object[0]);
            return null;
        }
        StringBuilder sb = new StringBuilder();
        boolean[] zArr = new boolean[7];
        for (int i = 0; i < jSONArray.length(); i++) {
            int iOptInt = jSONArray.optInt(i);
            if (iOptInt == 7) {
                iOptInt = 0;
            }
            if (!zArr[iOptInt]) {
                sb.append(b(iOptInt));
                sb.append(",");
                zArr[iOptInt] = true;
            }
        }
        sb.deleteCharAt(sb.length() - 1);
        return sb.toString();
    }

    @NonNull
    public static Map<String, Object> a(@NonNull JSONObject jSONObject) throws JSONException, ParseException, IllegalArgumentException {
        HashMap map = new HashMap();
        if (jSONObject.has(OTUXParamsKeys.OT_UX_DESCRIPTION)) {
            map.put("title", jSONObject.getString(OTUXParamsKeys.OT_UX_DESCRIPTION));
            if (jSONObject.has("start") && jSONObject.getString("start") != null) {
                Date dateA = a(jSONObject.getString("start"));
                if (dateA != null) {
                    map.put("beginTime", Long.valueOf(dateA.getTime()));
                    if (jSONObject.has("end") && jSONObject.getString("end") != null) {
                        Date dateA2 = a(jSONObject.getString("end"));
                        if (dateA2 != null) {
                            map.put("endTime", Long.valueOf(dateA2.getTime()));
                        } else {
                            POBLog.error("POBMRAIDUtil", "Invalid end format. end must be(yyyy-MM-DDTHH:MM:SS-xx:xx) or (yyyy-MM-DDTHH:MM-xx:xx)", new Object[0]);
                        }
                        if (jSONObject.has("location")) {
                            map.put("eventLocation", jSONObject.getString("location"));
                        }
                        if (jSONObject.has(OTUXParamsKeys.OT_UX_SUMMARY)) {
                            map.put(OTUXParamsKeys.OT_UX_DESCRIPTION, jSONObject.getString(OTUXParamsKeys.OT_UX_SUMMARY));
                        }
                        if (jSONObject.has("transparency")) {
                            map.put("availability", Integer.valueOf(jSONObject.getString("transparency").equals("transparent") ? 1 : 0));
                        }
                        if (jSONObject.has("recurrence")) {
                            map.put("rrule", b(jSONObject.getJSONObject("recurrence")));
                        }
                        return map;
                    }
                    throw new IllegalArgumentException("Invalid end.end can't be null.");
                }
                POBLog.error("POBMRAIDUtil", "Invalid start format. start must be(yyyy-MM-DDTHH:MM:SS-xx:xx) or (yyyy-MM-DDTHH:MM-xx:xx)", new Object[0]);
                throw new IllegalArgumentException("Invalid start format. start must be(yyyy-MM-DDTHH:MM:SS-xx:xx) or (yyyy-MM-DDTHH:MM-xx:xx)");
            }
            throw new IllegalArgumentException("Invalid start. start can't be null.");
        }
        throw new IllegalArgumentException("Invalid description. Description can't be null.");
    }

    private static String b(int i) {
        switch (i) {
            case 0:
                return "SU";
            case 1:
                return "MO";
            case 2:
                return "TU";
            case 3:
                return "WE";
            case 4:
                return "TH";
            case 5:
                return "FR";
            case 6:
                return "SA";
            default:
                POBLog.error("POBMRAIDUtil", "invalid day of week %s", Integer.valueOf(i));
                return null;
        }
    }

    private static Date a(@NonNull String str) throws ParseException {
        Date date = null;
        for (String str2 : a) {
            try {
                date = new SimpleDateFormat(str2, Locale.US).parse(str);
            } catch (ParseException e) {
                POBLog.error("POBMRAIDUtil", "Not able to parse date. %s", e.getLocalizedMessage());
            }
            if (date != null) {
                break;
            }
        }
        return date;
    }

    private static String a(@NonNull JSONArray jSONArray) {
        if (jSONArray.length() == 0) {
            POBLog.error("POBMRAIDUtil", "must have at least 1 day of the month if specifying repeating weekly", new Object[0]);
            return null;
        }
        StringBuilder sb = new StringBuilder();
        boolean[] zArr = new boolean[63];
        for (int i = 0; i < jSONArray.length(); i++) {
            int iOptInt = jSONArray.optInt(i);
            int i2 = iOptInt + 31;
            if (!zArr[i2]) {
                sb.append(a(iOptInt));
                sb.append(",");
                zArr[i2] = true;
            }
        }
        sb.deleteCharAt(sb.length() - 1);
        return sb.toString();
    }

    private static String a(int i) {
        if (i != 0 && i >= -31 && i <= 31) {
            return android.support.v4.media.session.a.f(i, "");
        }
        POBLog.error("POBMRAIDUtil", android.support.v4.media.session.a.f(i, "invalid day of month "), new Object[0]);
        return null;
    }

    public static boolean a(@NonNull Context context) {
        TelephonyManager telephonyManager = (TelephonyManager) context.getSystemService("phone");
        return (telephonyManager == null || telephonyManager.getSimState() == 1) ? false : true;
    }
}

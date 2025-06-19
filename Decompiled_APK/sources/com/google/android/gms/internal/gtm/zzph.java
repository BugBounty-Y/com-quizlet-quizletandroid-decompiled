package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.api.Status;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
final class zzph implements zzpf {
    @Override // com.google.android.gms.internal.gtm.zzpf
    public final zzpl zza(byte[] bArr) throws zzoy, JSONException {
        zzqh zzqhVarZzc;
        if (bArr == null) {
            throw new zzoy("Cannot parse a null byte[]");
        }
        if (bArr.length == 0) {
            throw new zzoy("Cannot parse a 0 length byte[]");
        }
        try {
            JSONObject jSONObject = new JSONObject(new String(bArr));
            JSONArray jSONArrayOptJSONArray = jSONObject.optJSONArray("runtime");
            if (jSONArrayOptJSONArray == null) {
                zzqhVarZzc = null;
            } else {
                zzqf zzqfVar = new zzqf();
                Object obj = jSONObject.get("resource");
                if (!(obj instanceof JSONObject)) {
                    throw new zzoy("Resource map not found");
                }
                zzqfVar.zzb(((JSONObject) obj).optString("version"));
                for (int i = 0; i < jSONArrayOptJSONArray.length(); i++) {
                    Object obj2 = jSONArrayOptJSONArray.get(i);
                    if (!(obj2 instanceof JSONArray) || ((JSONArray) obj2).length() != 0) {
                        zzqfVar.zza(zzoz.zza(obj2));
                    }
                }
                zzqhVarZzc = zzqfVar.zzc();
            }
            if (zzqhVarZzc != null) {
                zzhi.zzd("The runtime configuration was successfully parsed from the resource");
            }
            return new zzpl(Status.e, 0, null, zzqhVarZzc);
        } catch (zzoy unused) {
            throw new zzoy("The resource data is invalid. The runtime  configuration cannot be extracted from the JSON data");
        } catch (JSONException unused2) {
            throw new zzoy("The resource data is corrupted. The runtime configuration cannot be extracted from the JSON data");
        }
    }
}

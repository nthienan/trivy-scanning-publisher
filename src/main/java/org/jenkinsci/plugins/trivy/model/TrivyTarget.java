package org.jenkinsci.plugins.trivy.model;

import com.google.gson.annotations.SerializedName;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@NoArgsConstructor
@Getter
@Setter
public class TrivyTarget {
    @SerializedName("Target")
    private String name;
    @SerializedName("Vulnerabilities")
    private List<Vulnerability> vulnerabilities;

}

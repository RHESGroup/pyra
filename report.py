import os
from matplotlib.axis import Axis
from matplotlib.lines import Line2D
import pandas as pd
from owlready2 import *
from matplotlib.lines import Line2D
import matplotlib.pyplot as plt
import math

def main():
    owlready2.JAVA_EXE = "C:\\Program Files\\Java\\jdk1.8.0_241\\bin\\java"

    CWD = os.getcwd()

    # Load your ontology
    onto = get_ontology(CWD + "/popolata_v11.owl").load()

    # Sync reasoner
    sync_reasoner_hermit(infer_property_values = True)

    report_resources(onto)
    va_per_resource_detailed_report(onto)
    risk_assessment_overview(onto)
    threat_model_report(onto) 
    risk_assessment_detailed_report_from_threat_modelling(onto)
    risk_assessment_detailed_report_from_bron(onto)

    risk_assessment_overview_bar_chart(onto)
    vulnerability_assessment_overview_bar_chart(onto)
    va_detailed_report(onto)

# Set highlighting rules
def highlight_row(row):
    bg_colors_map = {
        'Very Low': '#E0FFF3',
        'Low': '#C7EFCE',
        'Medium': '#FFEC9C',
        'High': '#FF897A',
        'Very High': '#E14D4F'
    }

    text_colors_map = {
        'Very Low': '#009051',
        'Low': '#009051',
        'Medium': '#974706',
        'High': '#7A0306',
        'Very High': '#6F0307'
    }

    risk = row['Risk Level']
    background_color = bg_colors_map.get(risk, '#974706')
    text_color = text_colors_map.get(risk, '#006100')
    style = f"background-color: {background_color}; color: {text_color};"
    return [style] * len(row)

def highlight_vuln_row(row):
    bg_colors_map = {
        'Very Low': '#E0FFF3',
        'LOW': '#C7EFCE',
        'MEDIUM': '#FFEC9C',
        'HIGH': '#FF897A',
        'CRITICAL': '#E14D4F'
    }

    text_colors_map = {
        'Very Low': '#009051',
        'LOW': '#009051',
        'MEDIUM': '#974706',
        'HIGH': '#7A0306',
        'CRITICAL': '#6F0307'
    }

    risk = row['Severity Level']
    print(risk)
    background_color = bg_colors_map.get(risk, '#974706')
    text_color = text_colors_map.get(risk, '#006100')
    style = f"background-color: {background_color}; color: {text_color};"
    return [style] * len(row)

def top_10_resouces_at_risk(report):
    # Make a pretty ranking table in HTML
    # Compute the average risk for each resource (i.e. sum all the risks for a resource name and divide by the number of risks for that resource)
    avg_risk = report.groupby('Resource')['Risk'].mean()

    # Sort the resources by average risk
    avg_risk = avg_risk.sort_values(ascending=False)

    # Get the top 10 resources at risk
    top_10 = avg_risk.head(10)

    # Create a dataframe with the top 10 resources at risk
    top_10_df = pd.DataFrame({
        'Resource': top_10.index,
        'Average Risk': top_10.values
    })

    # Save the dataframe to HTML
    top_10_html_path = 'top_10_resources_at_risk.html'
    top_10_df.to_html(top_10_html_path, index=False)

def pie_with_legend(report):
    # Calculate the overall percentage of each risk
    overall_percentage = report.groupby('QRisk').size() / len(report) * 100

    # Get the counts of each risk
    risk_counts = report['QRisk'].value_counts()

    # Define custom colors
    risk_colors = {
        'Very Low': '#E0FFF3',
        'Low': '#C7EFCE',
        'Medium': '#FFEC9C',
        'High': '#FF897A',
        'Very High': '#E14D4F'
    }

    # Set a light background color
    plt.figure(figsize=(8, 8))
    plt.gca().set_facecolor('#F5F5F5')

    # Plot the pie chart with custom colors
    wedges, texts, autotexts = plt.pie(
        overall_percentage,
        labels=overall_percentage.index,
        autopct=lambda p: f'{p:.1f}%\n{int(p * len(report) / 100)}',  # Include both percentage and count
        colors=[risk_colors.get(r, 'blue') for r in overall_percentage.index],
        wedgeprops=dict(width=0.4, edgecolor='w')
    )

    # Add title with a larger font size
    plt.title('Overall Percentage of Risk', fontsize=16)

    # Equal aspect ratio ensures that pie is drawn as a circle.
    plt.axis('equal')

    # Add legend with risk counts
    legend_labels = [f'{risk} ({count})' for risk, count in zip(overall_percentage.index, risk_counts)]
    plt.legend(wedges, legend_labels, title='Risk Counts', loc='center left', bbox_to_anchor=(1, 0.5))

    # # Show the plot
    # plt.show()

    # Save the plot to a png file, with high resolution (300 dpi)
    plt.savefig('risk_pie_chart_1.png', dpi=300, bbox_inches='tight')

def generate_summary(report):
    # Create a summary dataframe
    summary_df = pd.DataFrame({
        'Total Risks': [len(report)],
        'Number of Very High Risks': [report[report['QRisk'] == 'Very High'].shape[0]],
        'Average Risk Percentage': [report.groupby('QRisk').size().mean()],
        'Most Common Risk Level': [report['QRisk'].mode().iloc[0]],
        'Resource Types with Most Risks': [report['Resource Type'].mode().iloc[0]],
        'Unique Resource Types': [report['Resource Type'].nunique()],
        'Unique Risk Levels': [report['QRisk'].nunique()],
        # Add more summary information as needed
    })

    # Save the summary dataframe to HTML
    summary_html_path = 'risk_summary_table.html'
    summary_df.to_html(summary_html_path, index=False)

# Copy of the risk_pie_chart function, but with a different name fake_risk_pie_chart
def fake_risk_pie_chart(report):
    # Get the counts of each risk
    risk_counts = {'Very High': 3,'High': 5, 'Medium': 8, 'Low': 5, 'Very Low': 0}

    # Compute percentages
    overall_percentage = {k: v / len(report) * 100 for k, v in risk_counts.items()}

    # Define custom colors for each risk category
    colors = {
        'Very Low': '#E0FFF3',
        'Low': '#C7EFCE',
        'Medium': '#FFEC9C',
        'High': '#FF897A',
        'Very High': '#E14D4F'
    }

    # Set the font size
    plt.rcParams['font.size'] = 15

    # Plot the pie chart with custom colors
    plt.figure(figsize=(8, 8))
    plt.pie(overall_percentage.values(), labels=overall_percentage.keys(), autopct='%1.1f%%', colors=[colors.get(r, 'blue') for r in overall_percentage.keys()])

    # Add a more descriptive title
    plt.title('Risk Distribution')

    # Equal aspect ratio ensures that pie is drawn as a circle.
    plt.axis('equal')

    # Add legend with risk counts
    legend_labels = [f'{risk}: {count}' for risk, count in zip(overall_percentage.keys(), risk_counts.values())]
    plt.legend(legend_labels, title='Threats per Risk Level', loc='upper right')

    # Save the plot to an SVG file
    plt.savefig('risk_pie_chart_fake_1.svg', bbox_inches='tight')

def risk_pie_chart(report):
    # Calculate the overall percentage of each risk
    overall_percentage = report.groupby('QRisk').size() / len(report) * 100

    # Get the counts of each risk
    risk_counts = report['QRisk'].value_counts()

    # Define custom colors for each risk category
    colors = {
        'Very Low': '#E0FFF3',
        'Low': '#C7EFCE',
        'Medium': '#FFEC9C',
        'High': '#FF897A',
        'Very High': '#E14D4F'
    }

    # Plot the pie chart with custom colors
    plt.figure(figsize=(8, 8))
    plt.pie(overall_percentage, labels=overall_percentage.index, autopct='%1.1f%%', colors=[colors.get(r, 'blue') for r in overall_percentage.index])

    # Add a more descriptive title
    plt.title('Risk Distribution')

    # Equal aspect ratio ensures that pie is drawn as a circle.
    plt.axis('equal')

    # Add legend with risk counts
    legend_labels = [f'{risk}: {count}' for risk, count in zip(overall_percentage.index, risk_counts)]
    plt.legend(legend_labels, title='Threats per Risk Level', loc='upper right')

    # # Show the plot
    # plt.show()

    # Save the plot to a png file, with high resolution (300 dpi)
    plt.savefig('risk_pie_chart_0.png', dpi=300, bbox_inches='tight')

    # Save the plot to an SVG file
    plt.savefig('risk_pie_chart_0.svg', bbox_inches='tight')

def draw_bar_chart(report):
    # Calculate the percentage of each risk within each type
    result_df = report.groupby(['Resource Type', 'QRisk']).size().unstack('QRisk', fill_value=0)
    result_df = result_df.div(result_df.sum(axis=1), axis=0) * 100

    # Define custom colors for each risk category
    colors = {
        'Very Low': '#C6EFCE',
        'Low': '#FFEB9C',
        'Medium': '#EFB78B',
        'High': '#F4BFC8',
        'Very High': '#F4BFC8'
    }

    # Plot the bar chart with custom colors
    ax = result_df.plot(kind='bar', stacked=True, figsize=(10, 6), color=[colors.get(r, 'blue') for r in result_df.columns])

    # Add labels and title
    plt.title('Percentage of Risk for Each Type')
    plt.xlabel('Type')
    plt.ylabel('Percentage')

    # Display the legend
    plt.legend(title='Risk', bbox_to_anchor=(1.05, 1), loc='upper left')

    # Show the plot
    plt.show()

def draw_pie_charts(report):
    # Calculate the percentage of each risk within each type
    result_df = report.groupby(['Resource Type', 'QRisk']).size().unstack('QRisk', fill_value=0)
    result_df = result_df.div(result_df.sum(axis=1), axis=0) * 100

    # Define custom colors for each risk category
    colors = {
        'Very Low': '#C6EFCE',
        'Low': '#FFEB9C',
        'Medium': '#EFB78B',
        'High': '#F4BFC8',
        'Very High': '#F4BFC8'
    }

    # Iterate through each 'Resource Type' and create a pie chart
    for resource_type in result_df.index:
        data = result_df.loc[resource_type]
        
        # Plot the pie chart with custom colors
        plt.figure(figsize=(6, 6))
        plt.pie(data, labels=data.index, autopct='%1.1f%%', colors=[colors.get(r, 'blue') for r in data.index])
        
        # Add title
        plt.title(f'Percentage of Risk for {resource_type}')
        
        # Show the plot
        plt.show()

def threats_report(onto):
    # Assuming you have a class called 'Resource' and a data property called 'CPE'
    resource_class = onto.Asset
    resources = set(resource_class.instances()) # using set because, somehow, I get some resources twice in the array

    # Sort resources by name
    capec_global_count = 0
    vuln_global_count = 0

    # Initialize the results list
    threats = []

    resources = sorted(resources, key=lambda x: x.name)
    for ont_resource in resources:
        # Count the number of isAffectedBy object properties
        capecs = ont_resource.isAffectedBy

        # Get the class of the resource
        resource_class = ont_resource.is_a[0].name

        # Iterate over the list of CAPECs to build the dataframe
        # We want each entry in the final excel file to be have: RESOURCE_NAME, CAPEC_NAME, CAPEC_LIKELIHOOD, CAPEC_SEVERITY, CAPEC_RISK

        for capec in capecs:
            # Get the name of each property object using the 'name' attribute
            name = capec.name
            likelihood_onto = capec.likelihood[0]
            severity_onto = capec.severity[0]

            # Strip any '*' from likelihood and severity
            likelihood = likelihood_onto.replace('*', '')
            severity = severity_onto.replace('*', '')

            # assign to likelihood a value from 1 to 5 based on the string value (i.e. "Very Low" = 1, "Low" = 2, etc.)
            likelihood_map = {
                "Very Low": 1,
                "Low": 2,
                "Medium": 3,
                "High": 4,
                "Very High": 5
            }

            likelihood_val = likelihood_map.get(likelihood, 4)
            severity_val = likelihood_map.get(severity, 4)
            risk = likelihood_val * severity_val
            
            qrisk = 0
            if risk >= 20:
                qrisk = 'Very High'
            elif risk >= 15 and risk <= 19:
                qrisk = 'High'
            elif risk >= 5 and risk <= 14:
                qrisk = 'Medium'
            elif risk >= 3 and risk <= 4:
                qrisk = 'Low'
            else:
                qrisk = 'Very Low'


            # Add to threats list
            threats.append({
                'Resource': ont_resource.name,
                'Resource Type': resource_class,
                'CAPEC': name,
                'Likelihood': likelihood_onto,
                'Severity': severity_onto,
                'Risk': risk,
                'QRisk': qrisk
            })

    # Write to pandas Excel report
    report = pd.DataFrame(threats)


    # Sort by risk
    report = report.sort_values(by=['Risk'], ascending=False)


    ######## Excel report ########
    # report = report.style.apply(highlight_row, axis=1)
    # report.to_excel("threats_3.xlsx", index=False)

    # # Convert DataFrame to HTML
    # # Guarantee minimum inner horizontal padding of 5px for each cell
    # report = report.set_table_styles([dict(selector="th, td", props=[("padding", "5px")])])

    # html_report = report.to_html(column_format="lllllcl", convert_css=True, index=False)

    # # Write HTML string to file
    # with open('report.html', 'w') as f:
    #     f.write(html_report)



    # Draw charts
    # risk_pie_chart(report)
    # pie_with_legend(report)
    fake_risk_pie_chart(report)
    # top_10_resouces_at_risk(report)


    # generate_summary(report)


    # # Write to LateX, also formatting so that rows with Risk > 10 are highlighted
    # def highlight_row(row):
    #     risk = row['Risk']
    #     background_color = "#F4BFC8" if risk > 19 else "#EFB78B" if risk > 11 else "#FFEB9C" if risk > 5 else "#C6EFCE"
    #     text_color = "#7A0306" if risk > 19 else "#974706" if risk > 11 else "#974706" if risk > 5 else "#006100"
    #     style = f"background-color: {background_color}; color: {text_color};"
    #     return [style] * len(row)

    # report = report.style.apply(highlight_row, axis=1)
    # report = report.to_html(column_format="lllllc", convert_css=True, index=False,)

    # # report = report.style.highlight_max(
    # #     props='cellcolor:[HTML]{FFFF00}; color:{red};'
    # #           'textit:--rwrap; textbf:--rwrap;')


    ############################################################################################################
    ################ Report on Latex
    ################
    # report = report.to_latex(column_format="lllllc", index=False)

    # # Write report to file
    # with open("table2.latex", "w") as file:
    #     file.write(report)

    ############################################################################################################


    # # styler = report.style
    # # styler.map(rating_color, subset="Risk")

    # # print("\n\n\n")
    # # print(styler.to_latex(column_format="lllllc"))

def data_flows_table(onto):
    results = []

    data_flow_class = onto.DataFlow
    data_flows = set(data_flow_class.instances()) # using set because, somehow, I get some resources twice in the array
    for data_flow in data_flows:
        # Get the name of the data flow
        name = data_flow.name

        # Get the name of the source
        source = data_flow.hasSource[0].name

        # Get the name of the destination
        destination = data_flow.hasDestination[0].name

        # Get the name of the Trust Boundary, after checking if the data flow instance has the 'crosses' object property
        trust_boundary = ""
        if len(data_flow.crosses) > 0:
            trust_boundary = data_flow.crosses[0].name

        # Add to threats list
        results.append({
            'Data Flow': name,
            'Source': source,
            'Destination': destination,
            'Bidirectional': 'No',
            'Crosses': trust_boundary
        })

    # Sort by data flow name
    results = sorted(results, key=lambda x: x['Data Flow'])

    # Now rename the data flows removing the A and B suffixes
    for result in results:
        result['Data Flow'] = result['Data Flow'][:-2]

    # Sort by data flow by number (e.g. DF1, DF2, DF3, DF10 etc.) (DF10 must be after DF9)
    results = sorted(results, key=lambda x: int(x['Data Flow'][2:]))

    final_results = []
    for result in results:
        # If no data flow with the same name is already in the final results, add it
        if not any(d['Data Flow'] == result['Data Flow'] for d in final_results):
            final_results.append(result)
        else: # set bidirectional to 'Yes' if the data flow is already in the final results
            for d in final_results:
                if d['Data Flow'] == result['Data Flow']:
                    d['Bidirectional'] = 'Yes'

    # Write to pandas LateX table
    report = pd.DataFrame(final_results)
    report = report.to_latex(column_format="lllll", index=False)

    # Print to standard output
    print(report)

def threat_model_report(onto):
    results = dict()
    total = 0

    for instance in onto.individuals():
        # If belongs to a valid class
        has_valid_class = True
        for cls in instance.is_a:
            if hasattr(cls, 'name') and (cls.name.startswith('CAPEC-') or cls.name == 'Threat'):
                has_valid_class = False
                break

        if has_valid_class and hasattr(instance, "isAffectedBy"):
            # Get the name of the instance
            name = instance.name

            # Get the class of the instance
            instance_class = instance.is_a[0].name

            # Get the isAffectedBy object properties
            is_affected_by = instance.isAffectedBy

            total += len(is_affected_by)

            # Iterate over the list of isAffectedBy object properties
            threat_categories = set()
            stride_labels = set()
            for prop in is_affected_by:
                # Get threat categories
                for cls in prop.is_a:
                    if cls.name.startswith('CAPEC-'):
                        cls_name = cls.name[6:]
                        threat_categories.add(cls_name)

                if hasattr(prop, "isLabelledWithSTRIDE"):
                    for stride in prop.isLabelledWithSTRIDE:
                        stride_name = stride.name
                        stride_labels.add(stride_name)

            # Remove '-A' and '-B' suffixes from the name of the instance (if present)
            name = name[:-2] if name.endswith('-A') or name.endswith('-B') else name

            # Check if individual exists in dictionary
            if len(is_affected_by) > 0:
                if name in results:
                    results[name]['count'] = results[name]['count'] + len(is_affected_by)
                    results[name]['threat_categories'].update(threat_categories)
                    results[name]['stride_labels'].update(set([l[0] for l in stride_labels]))
                else:
                    results[name] = {
                        'count': len(is_affected_by),
                        'threat_categories': threat_categories,
                        'stride_labels': set([l[0] for l in stride_labels])
                    }

    # For each resource, get the number of threats, threat categories and STRIDE labels
    final_results = []
    for name, data in results.items():
        labels = data['stride_labels']
        # Sort the labels in 'STRIDE' order
        labels = sorted(labels, key=lambda x: ['S', 'T', 'R', 'I', 'D', 'E'].index(x))

        final_results.append({
            'Target': name,
            'Threats Count': data['count'],
            'Threat Categories': ', '.join(data['threat_categories']),
            # 'STRIDE': ', '.join(labels)
        })

    # Add a total row
    final_results.append({
        'Target': 'Total',
        'Threats Count': sum([r['Threats Count'] for r in final_results]),
        'Threat Categories': '',
        # 'STRIDE': ''
    })

    # print(total)

    # Write to pandas LateX table, but set table width to 0.9\textwidth
    report = pd.DataFrame(final_results)
    report = report.to_latex(column_format="lc>{\\raggedright}p{.47\\textwidth}l", index=False, caption="Table with summarized results of the Threat Modeling phase.", label="tab:threat_model", longtable=True)

    # Print to standard output
    print(report)

def va_summary_report(onto):
    # We want to generate a report table with the following columns: Total Resources, Total CVEs, Total CWEs, Total ATT&CKs
    analyzed_resources = 0
    for r in onto.Asset.instances():
        has_cpe = hasattr(r, 'hasVulnerability') and len(r.CPE) > 0
        has_info = hasattr(r, 'vendor') and len(r.vendor) > 0 and hasattr(r, 'product') and len(r.product) > 0
        if has_cpe or has_info:
            analyzed_resources += 1

    total_resources = len(onto.Asset.instances())
    cves_count = len(onto.CVE.instances())
    cwes_count = len(onto.CWE.instances())
    attacks_count = len(onto.ATTACK.instances())

    print(f"Total Resources: {total_resources}")
    print(f"Analyzed Resources: {analyzed_resources}")
    print(f"Total CVEs: {cves_count}")
    print(f"Total CWEs: {cwes_count}")
    print(f"Total ATT&CKs: {attacks_count}")


    # Write to pandas LateX table
    report = pd.DataFrame([{
        'Total Resources': total_resources,
        'Analyzed Resources': analyzed_resources,
        'Total CVEs': cves_count,
        'Total CWEs': cwes_count,
        'Total ATT&CKs': attacks_count
    }])

    report = report.to_latex(column_format="ccccc", index=False)
    print(report)

def va_per_resource_report(onto):
    # We want to generate a report table with the following columns: Resource, Total CVEs, Total CWEs, Total ATT&CKs
    resources = onto.Asset.instances()
    results = []
    for resource in resources:
        # Get the name of the resource
        name = resource.name

        vulnerabilities = resource.hasVulnerability

        # Define sets for CWEs, CAPECs and ATT&CKs (# of CVES is the length of the vulnerabilities array)
        cwes = set()
        capecs = set()
        attacks = set()

        for vulnerability in vulnerabilities:
            # Get the CWEs
            if hasattr(vulnerability, 'hasCWE'):
                cwes.update(vulnerability.hasCWE)

            # Get CAPECs
            if hasattr(vulnerability, 'RelatedAttackPatterns'):
                related_capecs_lists = vulnerability.RelatedAttackPatterns
                if len(related_capecs_lists) > 0:
                    curr_capecs = []
                    for r in related_capecs_lists:
                        # Split the string (comma separated) and place items into capecs array and strip whitespace
                        curr_capecs += [c.strip() for c in r.split(',')]
                    capecs.update(curr_capecs)

            # Get ATT&CKs
            if hasattr(vulnerability, 'isExploitedBy'):
                attacks.update(vulnerability.isExploitedBy)

        # Check if all counts are 0
        if len(vulnerabilities) == 0:
            continue
        
        # Get a sorted array of CAPECS out of the set
        if resource.name == 'OS3':
            scapecs = sorted(list(capecs))

            for capec in scapecs:
                print(capec)

        # Add to results
        results.append({
            'Resource': name,
            'CVEs': len(vulnerabilities),
            'CWEs': len(cwes),
            'CAPECs': len(capecs),
            'ATT&CKs': len(attacks)
        })

    # Add a total row
    results.append({
        'Resource': 'Total',
        'CVEs': sum([r['CVEs'] for r in results]),
        'CWEs': sum([r['CWEs'] for r in results]),
        'CAPECs': sum([r['CAPECs'] for r in results]),
        'ATT&CKs': sum([r['ATT&CKs'] for r in results])
    })
    
    # Sort by resource name
    results = sorted(results, key=lambda x: x['Resource'])

    # Write to pandas LateX table
    report = pd.DataFrame(results)
    report = report.to_latex(column_format="lllll", index=False)

    # Print to standard output
    print(report)

def print_results(results, name):
    print("\\vspace{\\baselineskip}")
    print("\\centering{Vulnerabilities for \\textbf{" + name + "}}")
    print("\\begin{enumerate}")
    for result in results:
        print("    \\item \\textbf{CVE}:", result['CVE'])
        print("    \\begin{itemize}")
        print("        \\item \\textbf{CVSS}:", result['CVSS'])
        print("        \\item \\textbf{CWEs}:", result['CWEs'])
        print("        \\item \\textbf{CAPECs}:", result['CAPECs'])
        print("        \\item \\textbf{ATT\\&CKs}:", result['ATT&CKs'])
        print("    \\end{itemize}")
    print("\\end{enumerate}\n")

def va_per_resource_detailed_report(onto):
    # We want to generate one report for each resource with at least one vulnerability
    # The report will have the following columns: CVE, CWEs, CAPECs, ATT&CKs
    # The report will have the top 5 (evaluated by 'CVSS' data property score) vulnerabilities for each resource, sorted by CVSS score in descending order
    resources = onto.Asset.instances()

    # Sort resources by name
    resources = sorted(resources, key=lambda x: x.name)

    for resource in resources:
        # Get the name of the resource
        name = resource.name

        # Get the vulnerabilities
        vulnerabilities = resource.hasVulnerability

        # If the resource has no vulnerabilities, skip it
        if len(vulnerabilities) == 0:
            continue

        # Sort vulnerabilities by CVSS score
        # vulnerabilities = sorted(vulnerabilities, key=lambda x: float(x.CVSS[0]), reverse=True)

        # Keep only the top 5 vulnerabilities
        vulnerabilities = vulnerabilities[:3]

        # Sort vulnerabilities by CVSS score
        vulnerabilities = sorted(vulnerabilities, key=lambda x: float(x.CVSS[0]), reverse=True)

        results = []
        for vulnerability in vulnerabilities:
            # Get the CVE
            cve = vulnerability.hasCVE[0].name

            # Get the CWEs
            cwes = vulnerability.hasCWE

            # Get CAPECs
            capecs = set()
            if hasattr(vulnerability, 'RelatedAttackPatterns'):
                related_capecs_lists = vulnerability.RelatedAttackPatterns
                if len(related_capecs_lists) > 0:
                    curr_capecs = []
                    for r in related_capecs_lists:
                        # Split the string (comma separated) and place items into capecs array and strip whitespace
                        curr_capecs += [c.strip() for c in r.split(',')]
                    capecs.update(curr_capecs)

            # Get ATT&CKs
            attacks = vulnerability.isExploitedBy


            # Now make a unique string out of the CWEs, CAPECs and ATT&CKs
            if len(cwes) > 0:
                cwes = ', '.join([c.name for c in cwes])
            else:
                # cwes = '\\hspace{2.3em}-'
                cwes = 'N/A'

            if len(capecs) > 0:
                capecs = ', '.join(capecs)
            else:
                # capecs = '\\hspace{2.3em}-'
                capecs = 'N/A'

            if len(attacks) > 0:
                attacks = ', '.join([a.name for a in attacks])
            else:
                # attacks = '\\hspace{2.3em}-'
                attacks = 'N/A'

            cvss = "{:.1f}".format(round(vulnerability.CVSS[0], 1))

            # Add to results
            results.append({
                'CVE': cve,
                'CWEs': cwes,
                'CAPECs': capecs,
                'ATT&CKs': attacks,
                'CVSS': cvss
            })

        print_results(results, name)

        # # Generate a good label for LateX references to the table (e.g. 'table:OS1detailedVA')
        # label = name.replace(' ', '').replace('-', '').lower()
        # label = f"table:{label}detailedVA"

        # # Write to pandas LateX table (with resource name in caption)
        # report = pd.DataFrame(results)
        # report = report.to_latex(column_format="p{.22\linewidth}p{.16\linewidth}p{.16\linewidth}p{.16\linewidth}p{.10\linewidth}", index=False, caption=f"Vulnerabilities for {name}", label=label)

        # # Replace in report each occurrence of 'CVE & CWEs & CAPECs & ATT&CKs & CVSS' with '\\textbf{CVE} & \\textbf{CWEs} & \\textbf{CAPECs} & \\textbf{ATT\&CKs} & \\textbf{CVSS}'
        # report = report.replace('CVE & CWEs & CAPECs & ATT&CKs & CVSS', '\\textbf{CVE} & \\textbf{CWEs} & \\textbf{CAPECs} & \\textbf{ATT\\&CKs} & \\textbf{CVSS}')

        # # Print to standard output
        # print(report)

def report_resources(onto):
    # For each resource report CPE, vendor, product, version
    # place a '-' if the resource doesn't have one of the above
    # Finally, print as Latex table with the following columns: Resource, CPE, Vendor, Product, Version
    resources = onto.Asset.instances()
    results = []
    for resource in resources:
        # Get the name of the resource
        name = resource.name

        # Get the CPE
        cpe = resource.CPE[0] if len(resource.CPE) > 0 else 'MISSING'

        # Get the vendor
        vendor = resource.vendor[0] if len(resource.vendor) > 0 else 'MISSING'

        # Get the product
        product = resource.product[0] if len(resource.product) > 0 else 'MISSING'

        # Get the version
        version = resource.version[0] if len(resource.version) > 0 else 'MISSING'

        # Add to results
        results.append({
            'Resource': name,
            'CPE': cpe,
            'Vendor': vendor,
            'Product': product,
            'Version': version
        })
    
    # Sort by resource name
    results = sorted(results, key=lambda x: x['Resource'])

    # # Write to pandas LateX table
    # report = pd.DataFrame(results)
    # report = report.to_latex(column_format="lllll", index=False)

    # # Print to standard output
    # print(report)

    # Write to pandas Excel table
    report = pd.DataFrame(results)
    report = report.to_excel("resources.xlsx", index=False)

    # # # Write to pandas CSV table
    # report = pd.DataFrame(results)
    # report = report.to_csv("resources.csv", index=False)

def report_cpes(onto):
    # For each resource report CPE, vendor, product, version
    # place a '-' if the resource doesn't have one of the above
    # Finally, print as Latex table with the following columns: Resource, CPE, Vendor, Product, Version
    resources = onto.Asset.instances()
    results = []
    for resource in resources:
        # Get the name of the resource
        name = resource.name

        # Get the CPE
        cpe = resource.CPE[0] if len(resource.CPE) > 0 else ''

        # Escape the underscore character
        cpe = cpe.replace('_', '\\_')

        if (cpe != ''):
            # Add to results
            results.append({
                'Resource': name,
                'CPE': cpe
            })
    
    # Sort by resource name
    results = sorted(results, key=lambda x: x['Resource'])

    # Write to pandas LateX table
    report = pd.DataFrame(results)
    report = report.to_latex(column_format="ll", index=False)

    # Print to standard output
    print(report)

def risk_assessment_overview(onto):
    results = []
    
    for instance in onto.individuals():
        # If belongs to a valid class
        has_valid_class = True
        for cls in instance.is_a:
            if hasattr(cls, 'name') and (cls.name.startswith('CAPEC-') or cls.name == 'Threat'):
                has_valid_class = False
                break


        if has_valid_class and hasattr(instance, "isAffectedBy"):
            # Get the name of the resource
            name = instance.name

            very_low = 0
            low = 0
            medium = 0
            high = 0
            very_high = 0

            threats = instance.isAffectedBy

            if len(threats) == 0:
                continue

            # For each threat, compute the risk as likelihood * severity
            for threat in threats:
                # Get the likelihood and severity of each property object using the 'likelihood' and 'severity' attributes
                likelihood = threat.likelihood[0]
                severity = threat.severity[0]

                # assign to likelihood a value from 1 to 5 based on the string value (i.e. "Very Low" = 1, "Low" = 2, etc.)
                likelihood_map = {
                    "Very Low": 1,
                    "Low": 2,
                    "Medium": 3,
                    "High": 4,
                    "Very High": 5
                }

                likelihood_val = likelihood_map.get(likelihood, 4)
                severity_val = likelihood_map.get(severity, 4)
                risk = likelihood_val * severity_val

                if risk >= 20:
                    very_high += 1
                elif risk >= 15 and risk <= 19:
                    high += 1
                elif risk >= 5 and risk <= 14:
                    medium += 1
                elif risk >= 3 and risk <= 4:
                    low += 1
                else:
                    very_low += 1

            # Add to results
            results.append({
                'Resource': name,
                'Very Low': very_low,
                'Low': low,
                'Medium': medium,
                'High': high,
                'Very High': very_high
            })

    # Print a total of totals
    total_threats = sum([r['Very Low'] + r['Low'] + r['Medium'] + r['High'] + r['Very High'] for r in results])
    print(f"Total threats: {total_threats}")

    # Add a total row
    results.append({
        'Resource': '\\textbf{Total}',
        'Very Low': sum([r['Very Low'] for r in results]),
        'Low': sum([r['Low'] for r in results]),
        'Medium': sum([r['Medium'] for r in results]),
        'High': sum([r['High'] for r in results]),
        'Very High': sum([r['Very High'] for r in results])
    })

    # Write to pandas LateX table
    report = pd.DataFrame(results)

    # Sort by resource name
    report = report.sort_values(by=['Resource'])

    # Export to LateX
    report = report.to_latex(column_format="llllll", index=False, longtable=True, caption="Risk Assessment summary, showing the number of threats for each resource and risk level.", label="tab:risk_assessment_overview")   

    # Print to standard output
    print(report)

def risk_assessment_overview_bar_chart(onto):
    # We want to generate a bar chart with the number of threats for each risk level
    very_low = 0
    low = 0
    medium = 0
    high = 0
    very_high = 0

    for instance in onto.individuals():
        # If belongs to a valid class
        has_valid_class = True
        for cls in instance.is_a:
            if hasattr(cls, 'name') and (cls.name.startswith('CAPEC-') or cls.name == 'Threat'):
                has_valid_class = False
                break

        if has_valid_class and hasattr(instance, "isAffectedBy"):
            # Get the name of the resource
            name = instance.name

            # very_low = 0
            # low = 0
            # medium = 0
            # high = 0
            # very_high = 0

            threats = instance.isAffectedBy

            if len(threats) == 0:
                continue

            # For each threat, compute the risk as likelihood * severity
            for threat in threats:
                # Get the likelihood and severity of each property object using the 'likelihood' and 'severity' attributes
                likelihood = threat.likelihood[0]
                severity = threat.severity[0]

                # assign to likelihood a value from 1 to 5 based on the string value (i.e. "Very Low" = 1, "Low" = 2, etc.)
                likelihood_map = {
                    "Very Low": 1,
                    "Low": 2,
                    "Medium": 3,
                    "High": 4,
                    "Very High": 5
                }

                likelihood_val = likelihood_map.get(likelihood, 4)
                severity_val = likelihood_map.get(severity, 4)
                risk = likelihood_val * severity_val

                if risk >= 20:
                    very_high = 3 #+= 1
                elif risk >= 15 and risk <= 19:
                    high = 5 #+= 1
                elif risk >= 5 and risk <= 14:
                    medium = 8#+= 1
                elif risk >= 3 and risk <= 4:
                    low = 5 #+= 1
                else:
                    very_low += 1

    # Define custom colors for each risk category
    colors = {
        'Very Low': '#E6EBF5',
        'Low': '#C5D9F1',
        'Medium': '#9AB9E8',
        'High': '#7197DB',
        'Very High': '#4777D9'
    }

    # Plot the bar chart with custom colors
    plt.figure(figsize=(6, 6))
    plt.grid(True, axis='y', color='#e0e0e0', zorder=0)

    plt.bar(colors.keys(), [very_low, low, medium, high, very_high], color=colors.values(), zorder=1)

    # Add title with #3c3c3c color text
    plt.title('Threats per Risk Level', fontweight='bold', color='#3c3c3c')

    # Add the number of threats on top of each bar
    for i, v in enumerate([very_low, low, medium, high, very_high]):
        plt.text(i - 0.1, v + 0.5, str(v))

    # Add x-axis label
    plt.xlabel('Risk Level', fontweight='bold', color='#3c3c3c', labelpad=15)

    # Add y-axis label
    plt.ylabel('Number of Threats', fontweight='bold', color='#3c3c3c', labelpad=15)

    # Remove y-axis ticks
    plt.tick_params(axis='y', which='both', left=False, right=False, labelbottom=False)

    # Remove x-axis ticks
    plt.tick_params(axis='x', which='both', bottom=False, top=False, labelbottom=True)

    # Remove all spines from the plot
    plt.gca().spines['top'].set_visible(False)
    plt.gca().spines['right'].set_visible(False)
    plt.gca().spines['left'].set_visible(False)
    plt.gca().spines['bottom'].set_visible(False)

    # Show the plot
    # plt.show()

    # Write to SVG file
    plt.savefig('risk_assessment_overview_FAKE_bar_chart.svg', bbox_inches='tight')

def risk_assessment_overview_bar_chart_per_resource_type(onto):
    # Initialize dictionaries to store the counts of threats per risk level per resource type
    resource_types = set()
    threat_counts = {
        'Very Low': {},
        'Low': {},
        'Medium': {},
        'High': {},
        'Very High': {}
    }

    # Iterate over individuals in the ontology
    for instance in onto.individuals():
        has_valid_class = True
        resource_type = ""
        for cls in instance.is_a:
            if hasattr(cls, 'name'):
                if (cls.name.startswith('CAPEC-') or cls.name == 'Threat'):
                    has_valid_class = False
                    break
                else:
                    if cls.name in ['DataFlow', 'ExternalService', 'Device', 'Network', 'SystemSoftware', 'Information', 'SecurityMechanism', 'User']:
                        resource_type = cls.name
                        print(resource_type)

        if resource_type == "" or not has_valid_class:
            continue

        resource_types.update(resource_type)

        # If this is the first time we met the pair (risk_level, resource_type), initialize the count to 0
        for risk_level in threat_counts.keys():
            if resource_type not in threat_counts[risk_level]:
                threat_counts[risk_level][resource_type] = 0

        # Iterate over threats affecting the current resource
        if hasattr(instance, 'isAffectedBy'):
            threats = instance.isAffectedBy

            for threat in threats:
                likelihood = threat.likelihood[0]
                severity = threat.severity[0]

                # assign to likelihood a value from 1 to 5 based on the string value (i.e. "Very Low" = 1, "Low" = 2, etc.)
                likelihood_map = {
                    "Very Low": 1,
                    "Low": 2,
                    "Medium": 3,
                    "High": 4,
                    "Very High": 5
                }

                likelihood_val = likelihood_map.get(likelihood, 4)
                severity_val = likelihood_map.get(severity, 4)
                risk = likelihood_val * severity_val

                if risk >= 20:
                    risk_level = 'Very High'
                elif risk >= 15 and risk <= 19:
                    risk_level = 'High'
                elif risk >= 5 and risk <= 14:
                    risk_level = 'Medium'
                elif risk >= 3 and risk <= 4:
                    risk_level = 'Low'
                else:
                    risk_level = 'Very Low'

                # Increment the count for the current risk level and resource type
                threat_counts[risk_level][resource_type] += 1

    # Define custom colors for each risk category
    colors = {
        'Very Low': '#E6EBF5',
        'Low': '#C5D9F1',
        'Medium': '#9AB9E8',
        'High': '#7197DB',
        'Very High': '#4777D9'
    }

    # Remove from threat_counts the resource types that have no threats
    resource_types_with_threats = []

    for risk_level in threat_counts.keys():
        for resource_type in resource_types:
            if threat_counts[risk_level][resource_type] > 0:
                resource_types_with_threats.append(resource_type)

    # Plot the bar chart with custom colors
    plt.figure(figsize=(12, 6))
    bar_width = 0.15
    x_ticks = []
    x_positions = []

    for i, risk_level in enumerate(threat_counts.keys()):
        x = [j + i * bar_width for j in range(len(resource_types_with_threats))]
        y = [threat_counts[risk_level][resource_type] for resource_type in resource_types_with_threats]
        plt.bar(x, y, width=bar_width, color=colors[risk_level])
        x_ticks.extend(x)
        x_positions.append(x[len(resource_types_with_threats) // 2])

    # Add x-axis labels and ticks
    x_positions = range(len(resource_types_with_threats))
    plt.xticks(x_positions, resource_types_with_threats, rotation=45, ha='right')

    # Add title and legend
    plt.title('Number of threats per risk level per resource type', fontweight='bold')
    legend_elements = [Line2D([0], [0], color=colors[risk_level], lw=4, label=risk_level) for risk_level in threat_counts.keys()]
    plt.legend(handles=legend_elements, loc='upper right')

    # Show the plot
    plt.tight_layout()
    plt.show()

def risk_assessment_detailed_report_from_threat_modelling(onto):
    results = []
    
    for instance in onto.individuals():
        # If belongs to a valid class
        has_valid_class = True
        for cls in instance.is_a:
            if hasattr(cls, 'name') and (cls.name.startswith('CAPEC-') or cls.name == 'Threat'):
                has_valid_class = False
                break

        if not has_valid_class:
            continue

        # Get the name of the resource
        name = instance.name

        # Get the class of the resource
        class_name = instance.is_a[0].name #TODO probabilmente da modificare

        secmec = instance.isProtectedBy


        if has_valid_class and hasattr(instance, "isAffectedBy"):
            threats = instance.isAffectedBy

            if len(threats) == 0:
                continue

            # For each threat, compute the risk as likelihood * severity
            for threat in threats:
                # Get threat name
                threat_name = threat.name

                # Get the likelihood and severity of each property object using the 'likelihood' and 'severity' attributes
                likelihood = threat.likelihood[0]
                severity = threat.severity[0]

                # assign to likelihood a value from 1 to 5 based on the string value (i.e. "Very Low" = 1, "Low" = 2, etc.)
                likelihood_map = {
                    "Very Low": 1,
                    "Low": 2,
                    "Medium": 3,
                    "High": 4,
                    "Very High": 5
                }

                likelihood_val = likelihood_map.get(likelihood, 4)
                severity_val = likelihood_map.get(severity, 4)
                risk = likelihood_val * severity_val
                mitigatedRisk = risk

                modifier = 1
                if len(secmec) > 0 and len(threat.consequence) > 0:
                    dict_security_type = {"_Prevention": 1, "_Detection": 1, "_Recovery": 1, "_Correction": 1, "_Deflection": 1, "_Deterrence": 1}
                    pattern = r"\b(_Prevention|_Detection|_Recovery|_Correction|_Deflection|_Deterrence)\b"
                    dict_asset_type = {}
                    for c in instance.is_a:
                        if issubclass(c, onto.HasAsset):
                            while c != onto.HasAsset:
                                dict_asset_type[str(c).split(".")[1]] = 1 #non è necessario dividere lo score di ogni asset perchè si presume che nelle regole "protecs..." ci sia al massimo un asset type di ogni "gerarchia"
                                c = c.is_a[0]
                    weight_for_cons = 1/len(set(cons.split("::")[0] for cons in threat.consequence))
                    dict_security_property = {}
                    for cons in threat.consequence:
                        prop = cons.split("::")[0]
                        if prop == "Access Control" or prop == "Authorization":
                            dict_security_property["_Authorisation"] = weight_for_cons
                        else:
                            dict_security_property["_" + prop] = weight_for_cons
                    firewall = False
                    for sec_mec in secmec:
                        secMecClass = [subc for subc in sec_mec.is_a if issubclass(subc, onto.SecurityMechanism)]
                        for s in secMecClass:
                            for restriction in s.is_a:
                                print(restriction)
                                if not (isinstance(restriction, Restriction) and restriction.property.name == "protects" and restriction.type == ONLY):
                                    print(restriction)
                                    continue
                                print(str(restriction.value))
                                #estrarre tutti i security type da x e fare count()
                                weight_for_sec_type = len(re.findall(pattern, str(restriction.value)))
                                #assegnare a ogni security type con valore != 0 il risultato di count()
                                for sec_type in dict_security_type.keys():
                                    if dict_security_type[sec_type] != 0:
                                        dict_security_type[sec_type] = 1/weight_for_sec_type
                                input_values = {**dict_asset_type, **dict_security_property, **dict_security_type}
                                def replace_expression(expr, values):
                                    def replacer(match):
                                        key = match.group(1)
                                        return str(values.get(key, 0))
                                    return re.sub(r"popolata_v11\.(_\w+)", replacer, expr)
                                converted_expression = replace_expression(str(restriction.value), input_values)
                                print(converted_expression)
                                result = 1 - eval(converted_expression.replace("&", "*").replace("|", "+")) #TODO eventualmente cambiare come si calcola: considerare quale proprietà è mitigata e calcolarlo per quella proprietà solo una volta?
                                modifier = modifier * result
                        if onto.Firewall in secMecClass:    #TODO probabilmente da estendere ad altre classi dopo analisi
                            firewall = True
                    mitigatedRisk = modifier * mitigatedRisk
                    if firewall:
                        mitigatedRisk = str(mitigatedRisk) + "*"
                        firewall = False
                
                qrisk = 'N/A'
                mr = float(str(mitigatedRisk).split("*")[0])
                if mr >= 20:
                    qrisk = 'Very High'
                elif mr >= 15 and mr <= 19:
                    qrisk = 'High'
                elif mr >= 5 and mr <= 14:
                    qrisk = 'Medium'
                elif mr >= 3 and mr <= 4:
                    qrisk = 'Low'
                else:
                    qrisk = 'Very Low'

                # Add to results
                if risk != mitigatedRisk:
                    results.append({
                        'Resource': name,
                        'Type': class_name,
                        'Threat': threat_name,
                        # 'Likelihood': likelihood,
                        # 'Severity': severity,
                        'Risk': risk,
                        'Mitigated Risk': mitigatedRisk,
                        'Risk Level': qrisk
                    })
                else:
                    results.append({
                        'Resource': name,
                        'Type': class_name,
                        'Threat': threat_name,
                        # 'Likelihood': likelihood,
                        # 'Severity': severity,
                        'Risk': risk,
                        'Mitigated Risk': 'N/A',
                        'Risk Level': qrisk
                    })

    # Construct a new array to limit the number of results
    final_results = []

    # Sort by risk
    results = sorted(results, key=lambda x: x['Risk'], reverse=True)

#    for result in results:
#        name = result['Resource']
#        class_name = result['Type']
#
#        # If there are already 2 results for this resource, skip it
#        if len(final_results) > 0 and len([r for r in final_results if r['Resource'] == name]) >= 2:
#            continue
#
#        # If there are already 3 results for this resource type, skip it
#        if len(final_results) > 0 and len([r for r in final_results if r['Type'] == class_name]) >= 6:
#            continue
#
#        # If there are already 3 results for this threat, skip it
#        if len(final_results) > 0 and len([r for r in final_results if r['Threat'] == result['Threat']]) >= 3:
#            continue
#
#        # If qrisk is Very High and there are already 5 results for this risk level, skip it
#        if len(final_results) > 0 and result['Risk Level'] == 'Very High' and len([r for r in final_results if r['Risk Level'] == 'Very High']) >= 8:
#            continue
#
#        # If qrisk is High and there are already 3 results for this risk level, skip it
#        if len(final_results) > 0 and result['Risk Level'] == 'High' and len([r for r in final_results if r['Risk Level'] == 'High']) >= 5:
#            continue
#
#        # If qrisk is Medium and there are already 6 results for this risk level, skip it
#        if len(final_results) > 0 and result['Risk Level'] == 'Medium' and len([r for r in final_results if r['Risk Level'] == 'Medium']) >= 6:
#            continue
#
#        # If qrisk is Low and there are already 4 results for this risk level, skip it
#        if len(final_results) > 0 and result['Risk Level'] == 'Low' and len([r for r in final_results if r['Risk Level'] == 'Low']) >= 4:
#            continue
#
#        final_results.append(result)

    # Write to Excel table
    # report = pd.DataFrame(final_results)
    report = pd.DataFrame(results)

    report = report.style.apply(highlight_row, axis=1)

    new_row = pd.DataFrame({"Resource": ["* = the mitigated risk could not reflect the actual risk(see documentation)"]})#TODO da provare
    combined_report = pd.concat([report.data, new_row], ignore_index=True)

    # Salva su Excel con stile applicato (esclusa la riga aggiuntiva)
    with pd.ExcelWriter("risk_assessment_detailed_report_from_threat_modelling.xlsx") as writer:
        report.to_excel(writer, index=False, startrow=0)
        # Inserisci manualmente la nota
        combined_report.tail(1).to_excel(writer, index=False, startrow=len(combined_report), header=False)

    # Write to file
    #report.to_excel("risk_assessment_detailed_report_from_threat_modelling.xlsx", index=False)


    # # Write to pandas LateX table
    # report = pd.DataFrame(final_results)
    # report = report.to_latex(column_format="llllll", index=False, longtable=True, caption="Extract of the detailed Risk Assessment report.", label="tab:risk_assessment_detailed")

    # # Print to standard output
    # print(report)

def risk_assessment_detailed_report_from_bron(onto):
    # ____________________________________________
    #| Resource | capec | score | mitigated_score |
    
    results = []
    
    for instance in onto.Risk.instances():

        conv_table = {"Very Low": 1, "Low": 2, "Medium": 3, "High": 4, "Very High": 5}
        
        resource = instance.hasSourceAsset[0]
        capec = instance.hasSourceCAPEC[0]
        vuln = instance.hasSourceVuln
        # Get the name of the resource
        name = resource.name

        # Get the class of the resource
        class_name = resource.is_a[0].name


        if len(instance.mitigatedCapecScore) > 0:
            risk = math.ceil(float(str(instance.mitigatedCapecScore[0]).split("*")[0]))
        else:
            risk = conv_table.get(instance.hasSourceCAPEC[0].severity[0], 4) * conv_table.get(instance.hasSourceCAPEC[0].likelihood[0], 4)
        qrisk = 'N/A'
        if risk >= 20:
            qrisk = 'Very High'
        elif risk >= 15 and risk <= 19:
            qrisk = 'High'
        elif risk >= 5 and risk <= 14:
            qrisk = 'Medium'
        elif risk >= 3 and risk <= 4:
            qrisk = 'Low'
        else:
            qrisk = 'Very Low'
        # Add to results
        if len(instance.mitigatedCapecScore) > 0:
            results.append({
                'Resource': name,
                'Capec': capec.name,
                'Risk': int(instance.capecScore[0]),
                'Mitigated Risk': instance.mitigatedCapecScore[0],
                'Risk Level': qrisk
            })
        else:
            results.append({
                'Resource': name,
                'Capec': capec.name,
                'Risk': conv_table.get(instance.hasSourceCAPEC[0].severity[0], 4) * conv_table.get(instance.hasSourceCAPEC[0].likelihood[0], 4),
                'Mitigated Risk': 'N/A',
                'Risk Level': qrisk
            })

    # Sort by risk
    results = sorted(results, key=lambda x: x['Risk'], reverse=True)

    # Write to Excel table
    report = pd.DataFrame(results)

    report = report.style.apply(highlight_row, axis=1)

    new_row = pd.DataFrame({"Resource": ["* = the mitigated risk could not reflect the actual risk(see documentation)"]})
    combined_report = pd.concat([report.data, new_row], ignore_index=True)

    # Salva su Excel con stile applicato (esclusa la riga aggiuntiva)
    with pd.ExcelWriter("risk_assessment_detailed_report_from_bron.xlsx") as writer:
        report.to_excel(writer, index=False, startrow=0)
        # Inserisci manualmente la nota
        combined_report.tail(1).to_excel(writer, index=False, startrow=len(combined_report), header=False)


    # Write to file
    #report.to_excel("risk_assessment_detailed_report_from_bron.xlsx", index=False)


    # # Write to pandas LateX table
    # report = pd.DataFrame(final_results)
    # report = report.to_latex(column_format="llllll", index=False, longtable=True, caption="Extract of the detailed Risk Assessment report.", label="tab:risk_assessment_detailed")

    # # Print to standard output
    # print(report)

def vulnerability_assessment_overview_bar_chart(onto):
    # Take all individuals of the Vulnerability class
    vulnerabilities = onto.Vulnerability.instances()

    # Define custom colors for each vulnerability severity level
    colors = {
        'Low': '#C5D9F1',
        'Medium': '#9AB9E8',
        'High': '#7197DB',
        'Critical': '#4777D9'
    }

    # Initialize a dictionary to store the number of vulnerabilities per severity level
    vulnerability_counts = {
        '0.1 - 3.9': 0,
        '4.0 - 6.9': 0,
        '7.0 - 8.9': 0,
        '9.0 - 10.0': 0
    }

    # Iterate over the vulnerabilities
    for vulnerability in vulnerabilities:
        # Get the severity level
        score = vulnerability.CVSS[0]

        # Map score to qualitative severity level
        if score >= 0.1 and score <= 3.9:
            severity = '0.1 - 3.9'
        elif score >= 4.0 and score <= 6.9:
            severity = '4.0 - 6.9'
        elif score >= 7.0 and score <= 8.9:
            severity = '7.0 - 8.9'
        else:
            severity = '9.0 - 10.0'

        # Increment the count for the current severity level
        vulnerability_counts[severity] += 1

    # Plot the bar chart with custom colors
    plt.figure(figsize=(6, 6))
    plt.grid(True, axis='y', color='#e0e0e0', zorder=0)

    plt.bar(vulnerability_counts.keys(), [vulnerability_counts[severity] for severity in vulnerability_counts.keys()], color=colors.values(), zorder=1)

    # Add title with #3c3c3c color text
    plt.title('Vulnerabilities per Severity Score', fontweight='bold', color='#3c3c3c')

    # Add the number of vulnerabilities on top of each bar
    for i, v in enumerate([vulnerability_counts[severity] for severity in vulnerability_counts.keys()]):
        plt.text(i - 0.1, v + 0.5, str(v))

    # Add x-axis label
    plt.xlabel('Severity Score', fontweight='bold', color='#3c3c3c', labelpad=15)

    # Add y-axis label
    plt.ylabel('Number of Vulnerabilities', fontweight='bold', color='#3c3c3c', labelpad=15)

    # Remove x-axis and y-axis ticks
    plt.tick_params(axis='x', which='both', bottom=False, top=False, labelbottom=True)
    plt.tick_params(axis='y', which='both', left=False, right=False)

    # Remove all spines from the plot
    plt.gca().spines['top'].set_visible(False)
    plt.gca().spines['right'].set_visible(False)
    plt.gca().spines['left'].set_visible(False)
    plt.gca().spines['bottom'].set_visible(False)

    # # Show the plot
    # plt.show()

    # Write to SVG file
    plt.savefig('vulnerability_assessment_overview_bar_chart.svg', bbox_inches='tight')

def va_detailed_report(onto):
    # We want to generate a report contining the following columns: Resource, CVE, CWEs, CAPECs, ATT&CKs, Severity
    # where severity is the 'BaseSeverity' data property of the Vulnerability class
    resources = onto.Asset.instances()

    # For each resource, get the vulnerabilities
    results = []

    for resource in resources:
        # Get the name of the resource
        name = resource.name

        # Get the vulnerabilities
        vulnerabilities = resource.hasVulnerability

        # If the resource has no vulnerabilities, skip it
        if len(vulnerabilities) == 0:
            continue

        # Sort vulnerabilities by CVSS score
        vulnerabilities = sorted(vulnerabilities, key=lambda x: float(x.CVSS[0]), reverse=True)

        for vulnerability in vulnerabilities:
            # Get the CVE
            cve = vulnerability.hasCVE[0]
            cve_name = cve.name

            # Get the CWEs
            cwes = vulnerability.hasCWE

            # Get CAPECs
            capecs = set()
            if hasattr(vulnerability, 'RelatedAttackPatterns'):
                related_capecs_lists = vulnerability.RelatedAttackPatterns
                if len(related_capecs_lists) > 0:
                    curr_capecs = []
                    for r in related_capecs_lists:
                        # Split the string (comma separated) and place items into capecs array and strip whitespace
                        curr_capecs += [c.strip() for c in r.split(',')]
                    capecs.update(curr_capecs)

            # Get ATT&CKs
            attacks = vulnerability.isExploitedBy

            # Get severity score
            severity_score = cve.BaseScore[0]

            # Get the severity
            severity = cve.BaseSeverity[0]

            # Now make a unique string out of the CWEs, CAPECs and ATT&CKs
            if len(cwes) > 0:
                cwes = ', '.join([c.name for c in cwes])
            else:
                # cwes = '\\hspace{2.3em}-'
                cwes = 'N/A'

            if len(capecs) > 0:
                capecs = ', '.join(capecs)
            else:
                # capecs = '\\hspace{2.3em}-'
                capecs = 'N/A'

            if len(attacks) > 0:
                attacks = ', '.join([a.name for a in attacks])
            else:
                # attacks = '\\hspace{2.3em}-'
                attacks = 'N/A'

            # Add to results
            results.append({
                'Resource': name,
                'CVE': cve_name,
                'CWEs': cwes,
                'CAPECs': capecs,
                'ATT&CK': attacks,
                'Severity Score': severity_score,
                'Severity Level': severity
            })

    # Write Excel table
    report = pd.DataFrame(results)

    # Sort by severity score in descending order
    report = report.sort_values(by=['Severity Score'], ascending=False)

    report = report.style.apply(highlight_vuln_row, axis=1)

    # Write to file
    report.to_excel("vulnerability_assessment_detailed_report.xlsx", index=False)


# Run the main function
if __name__ == "__main__":
    main()
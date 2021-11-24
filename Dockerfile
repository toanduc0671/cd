ARG VERSION=1.0.0
FROM 10.60.129.132:8890/willhallonline/ansible:2.9-centos-7
COPY kubespray roles advanced-cluster-with-monitoring-logging.yml ansible.cfg requirements.txt /opt/k8s/
WORKDIR /opt/k8s
RUN pip install --trusted-host 10.60.129.132 \
-i http://10.60.129.132/repository/PyPI-internal/simple -r requirements.txt
ENTRYPOINT "ansible-playbook -i inventory/k8s-cluster/inventory.ini advanced-cluster-with-monitoring-logging.yml"

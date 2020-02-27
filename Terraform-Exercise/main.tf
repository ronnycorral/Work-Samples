provider "aws" {
  region                  = "us-west-2"
} 

// always get latest version of ami
data "aws_ami" "latest-ubuntu" {
most_recent = true
owners = ["099720109477"] # Canonical

  filter {
      name   = "name"
      values = ["ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-*"]
  }

  filter {
      name   = "virtualization-type"
      values = ["hvm"]
  }
}

resource "aws_instance" "web" {
  ami = data.aws_ami.latest-ubuntu.id
  instance_type = "t3.micro"
  key_name = "test_ec2_key"
  vpc_security_group_ids = [aws_security_group.mediawiki-web-sg.id]
  tags = {
        Name = "mediawiki"
  }
  subnet_id = aws_subnet.public.id
  depends_on = [aws_internet_gateway.gw]
}

//public key from my AWS key pair
resource "aws_key_pair" "terraform_ec2_key" {
  key_name = "test_ec2_key"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBdJ6tnae8wFTf4ww+zI/dgeP3x1OqjaR+nawWulT6KzaGqtUc00rXe4i0Cu+N7uEfauJKfIgz9vasVWb/D8vmp5N/Aq1eiaBesIkXf3L9VqR0LIkXd3ctQV5Dis5n7EXvj0K0IA51JuBzJGVCDST/Ua1teT8ADPHuSXQ5o+ubAs2GKngqcuW8aqphIgVf7z6jNDkZSFLGXaZrTAUI+L0ebPKZnqYSlluJ2Tu+qdkos0CQADuDAS/7XvtAe206UkT+BLN8jfq7nljjGBAGDVTZjXQrqhk/rcmsySKBdUwdaVntLRNeqtB7APe4wHlZ5y37ImINry7XXnFerwPqwaob TESTKEY"
}

